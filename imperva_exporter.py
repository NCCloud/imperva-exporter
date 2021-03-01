#!/usr/bin/env python3

from datetime import datetime
import argparse
import calendar
import logging
import os
import time
import urllib.parse

import dateutil.parser
import requests


def unix_timestamp(time_string=None):
    if time_string:
        return calendar.timegm(dateutil.parser.parse(time_string).utctimetuple())
    else:
        return calendar.timegm(datetime.utcnow().utctimetuple())


def describe_event(ev):
    description = f'Imperva event `{ev["eventType"]} {ev["eventTarget"]}` happened at `{ev["eventTime"]}`'

    if ev.get('suspectedTarget'):
        description += '\nPossible attack target: `{} via {}`'.format(
            ev['suspectedTarget'].get('DST_IP'), ev['suspectedTarget'].get('DST_PORT_PROTOCOL')
        )

    if ev['eventType'].startswith('DDOS_STOP'):
        description += '\nAttack summary: `bwTotal: {}` `bwBlocked: {}` `ppsTotal: {}` `ppsBlocked: {}`'.format(
            ev.get('bwTotal'), ev.get('bwBlocked'), ev.get('ppsTotal'), ev.get('ppsBlocked')
        )
    LOG.info(description)

    dashboard_url = 'https://my.imperva.com/infra-protect/dashboard/ip-range/v3?'
    dashboard_url += urllib.parse.urlencode({
        'series': 'Blocked', 'vb': 'Traffic', 'accountId': IMPERVA_ACC_ID, 'rangeIp': ev['eventTarget'],
        'rs':  1000 * (unix_timestamp(ev["eventTime"]) - 480), 're': 1000 * (unix_timestamp() + 480)
    })
    return f'{description} \nDashboard: <{dashboard_url}|{ev["eventTarget"]}>'


def get_imperva_top_target(ev, end_time):
    target = {}

    endpoint = 'https://my.imperva.com/api/v1/infra/top-table'
    with requests.Session() as imperva:
        for data_type in ['DST_IP', 'DST_PORT_PROTOCOL']:
            try:
                response = imperva.post(endpoint, data={
                    'api_id': IMPERVA_API_ID, 'api_key': IMPERVA_API_KEY, 'account_id': IMPERVA_ACC_ID,
                    'start': unix_timestamp(ev['eventTime']) * 1000, 'end': end_time,
                    'metric_type': 'PPS', 'mitigation_type': 'BLOCK', 'aggregation_type': 'PEAK',
                    'range_type': 'BGP', 'ip_range': ev['eventTarget'], 'data_type': data_type
                })
                if not response.ok:
                    response.raise_for_status()

                stats = response.json()['stats']
                if stats:
                    target[data_type] = stats[0]['object']
            except Exception as e:
                LOG.exception(e)
    return target


def get_imperva_events(prefixes, check_interval, get_top=False):
    events, err = [], False

    epoch_time = unix_timestamp()
    start_time = (epoch_time - check_interval) * 1000
    end_time = epoch_time * 1000

    endpoint = 'https://my.imperva.com/api/v1/infra/events'
    with requests.Session() as imperva:
        try:
            response = imperva.post(endpoint, data={
                'api_id': IMPERVA_API_ID, 'api_key': IMPERVA_API_KEY, 'account_id': IMPERVA_ACC_ID,
                'ip_prefix': prefixes, 'start': start_time, 'end': end_time
            })
            if not response.ok:
                response.raise_for_status()

            json_response = response.json()
            if json_response.get('events'):
                for ev in sorted(json_response['events'], key=lambda t: t.get('eventTime', 0)):
                    if ev['eventType'].startswith('DDOS'):
                        if get_top and ev['eventType'].startswith('DDOS_START'):
                            ev['suspectedTarget'] = get_imperva_top_target(ev, end_time)
                        events.append(ev)
        except Exception as e:
            LOG.exception(e)
            err = True
    return events, err


def slack_notify(notification, slack_room, slack_team):
    if slack_team:
        notification = f'{slack_team} {notification}'
    try:
        response = requests.post(SLACK_HOOK_URL, headers={'Content-type': 'application/json'},
                                 json={'channel': f'#{slack_room}', 'text': notification})
        if response.ok and response.text == 'ok':
            LOG.info(f'Notified #{slack_room}')
        else:
            LOG.error(f'Slack API error: {response.status_code} {response.text}')
    except Exception as e:
        LOG.exception(e)


def prom_init(prefixes, prom_port, prom_init_hours):
    from prometheus_client import start_http_server, generate_latest, Gauge, Counter

    prom = {
        'ddos_status': Gauge('imperva_prefix_ddos_status', '1 when the prefix is under attack', ['prefix']),
        'ddos_total': Counter('imperva_prefix_ddos', 'Recorded attacks on the prefix', ['prefix']),
        'failure_duration': Gauge('imperva_api_failure_duration', 'Time without any Imperva data in seconds'),
        'errors_total': Counter('imperva_api_errors', 'Total errors while querying Imperva API')
    }

    for metric in prom.keys():
        if metric.startswith('ddos'):
            for prefix in prefixes:
                generate_latest(prom[metric].labels(prefix=prefix))
        else:
            generate_latest(prom[metric])

    last_events, err = get_imperva_events(prefixes, prom_init_hours * 3600)
    if err:
        LOG.error(f'Unable to load historical context from Imperva for last {prom_init_hours}h')
    else:
        LOG.info(f'Seeded Prometheus metrics with {prom_init_hours}h of Imperva context.')
    for event in last_events:
        prom_push_event(prom, event)

    LOG.info(f'Exporting Prometheus metrics on :{prom_port}')
    start_http_server(prom_port)
    return prom


def prom_push_event(prom, event):
    ddos_gauge = 0
    if event['eventType'].startswith('DDOS_START'):
        prom['ddos_total'].labels(prefix=event['eventTarget']).inc()
        ddos_gauge = 1
    prom['ddos_status'].labels(prefix=event['eventTarget']).set(ddos_gauge)


def watch_loop(prefixes, interval, overlap, threshold, prom_port, prom_init_hours, slack_room, slack_team):
    if prom_port:
        prom = prom_init(prefixes, prom_port, prom_init_hours)
    if slack_room:
        LOG.info(f'Will notify Slack channel #{slack_room} about new events')
    LOG.info(f'Monitoring events for {prefixes} every {interval}s with {overlap}s overlap')

    err_count, missed_beat_multiplier = 0, 1
    last_event_time = 0
    while True:
        events, err = get_imperva_events(prefixes, missed_beat_multiplier * interval + overlap, get_top=True)

        if err:
            err_count += 1
            missed_beat_multiplier += 1
            prom['errors_total'].inc()
            prom['failure_duration'].set(missed_beat_multiplier * interval)
        elif err_count > 0:
            err_count, missed_beat_multiplier = 0, 1
            prom['failure_duration'].set(0)
            LOG.info('Recovered from failure and caught up with missed time frames')

        if err_count >= threshold:
            message = f'Imperva API consecutive error count reached configured threshold: `{err_count}`'
            LOG.error(message)
            if slack_room:
                slack_notify(message, slack_room, slack_team)
            err_count = 0

        # TODO: store and destroy event objects on start/stop events
        for event in events:
            event_time = unix_timestamp(event['eventTime'])
            if event_time > last_event_time:
                event_description = describe_event(event)
                last_event_time = event_time
                if slack_room:
                    slack_notify(event_description, slack_room, slack_team)
                if prom_port:
                    prom_push_event(prom, event)
            else:
                LOG.debug(f'Already registered `{event["eventType"]} {event["eventTarget"]}` at `{event["eventTime"]}`')
        time.sleep(interval)


def parse_args():
    parser = argparse.ArgumentParser(description='Check DDoS events on prefixes protected by Imperva',
                                     epilog='required env vars: IMPERVA_API_ID, IMPERVA_API_KEY, IMPERVA_ACC_ID')

    parser.add_argument('prefix', action='append', nargs='+', help='ip prefix(es), separated by space')
    parser.add_argument('-w', '--watch', action='store_true', help='keep running and and collect events continuously')
    parser.add_argument('-i', '--interval', type=int, metavar='N', default=300, help='check last N seconds, default: 300')
    parser.add_argument('-o', '--overlap', type=int, metavar='N', default=300, help='compensate latency, default: 300 sec (watch mode only)')
    parser.add_argument('-t', '--threshold', type=int, metavar='N', default=100, help='report after N fails, default: 100 (watch mode only)')
    parser.add_argument('-v', '--debug', action='store_true', help='enable debug output')

    prom = parser.add_argument_group('Prometheus metrics (watch mode only, needs prometheus_client module)')
    prom.add_argument('--prom-port', type=int, metavar='PORT', help='export Prometheus metrics on this port')
    prom.add_argument('--prom-init-hours', type=int, metavar='N', default=24, help='preload N hours of historical context, default: 24')

    slack = parser.add_argument_group('Slack notifications (watch mode only)')
    slack.add_argument('--slack-room', metavar='room-name', help='send event notifications to this Slack channel, SLACK_HOOK_URL env must be set')
    slack.add_argument('--slack-team', metavar='<!subteam^ID|@team>', help='mention this team in the Slack notification')
    return parser.parse_args()


def validate_args(args):
    assert None not in {IMPERVA_API_ID, IMPERVA_API_KEY, IMPERVA_ACC_ID}  # auth always required
    assert args.interval >= args.overlap  # compensation overlap should be ≤ check interval
    if args.prom_port or args.slack_room:
        assert args.watch  # Slack notifications and Prometheus metrics need watch mode (-w)
    if args.slack_room:
        assert SLACK_HOOK_URL  # Slack hook url is required to send notifications


def main():
    args = parse_args()
    validate_args(args)
    prefixes = args.prefix[0]

    logging.basicConfig(format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
                        level=logging.DEBUG if args.debug else logging.INFO)
    global LOG
    LOG = logging.getLogger(__name__)

    if args.watch:
        watch_loop(prefixes, args.interval, args.overlap, args.threshold,
                   args.prom_port, args.prom_init_hours, args.slack_room, args.slack_team)
    else:
        events, err = get_imperva_events(prefixes, args.interval)
        if not err:
            for event in events:
                describe_event(event)
        else:
            LOG.error('Unable to fetch data from Imperva API')


if __name__ == "__main__":
    IMPERVA_API_ID, IMPERVA_API_KEY, IMPERVA_ACC_ID = os.environ.get('IMPERVA_API_ID'), os.environ.get('IMPERVA_API_KEY'), os.environ.get('IMPERVA_ACC_ID')
    SLACK_HOOK_URL = os.environ.get('SLACK_HOOK_URL')

    main()
