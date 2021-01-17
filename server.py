import argparse
import boto3
import json
import logging
import time

from functools import partial
from threading import Thread
from twisted.internet import reactor, defer
from twisted.names import client, cache, dns, error, server

logger = logging.getLogger(__name__)


class DynamicResolver(object):
    def __init__(self, hostmap={}, ttl=30):
        self.hostmap = hostmap
        self.ttl = ttl

    def _is_resolvable(self, query):
        if query.type == dns.A:
            return query.name.name.decode() in self.hostmap
        return False

    def _handle_dns_query(self, query):
        answers = [
            dns.RRHeader(
                name=query.name.name,
                payload=dns.Record_A(address=self.hostmap[query.name.name.decode()]),
                ttl=self.ttl,
            )
        ]
        authority = []
        additional = []
        return answers, authority, additional

    def query(self, query, timeout=None):
        if self._is_resolvable(query):
            logging.debug(f"{query.name.name.decode()} is resolvable")
            return defer.succeed(self._handle_dns_query(query))
        return defer.fail(error.DomainError())


def serialize_ec2_instance(tag_key, ec2_instance):
    return (
        ec2_instance.private_ip_address,
        next(
            (tag["Value"] for tag in ec2_instance.tags or [] if tag["Key"] == tag_key),
            None,
        ),
    )


def hostmap_updater(aws_credentials_path, tag_key, update_interval, hostmap):
    logging.info("Starting hostmap updater...")

    with open(aws_credentials_path, "rb") as fh:
        ec2_clients = [
            boto3.session.Session(
                aws_access_key_id=credentials["aws_access_key_id"],
                aws_secret_access_key=credentials["aws_secret_access_key"],
                region_name=credentials["aws_region"],
            ).resource("ec2")
            for credentials in json.loads(fh.read())
        ]

    while True:
        hostmap.update(
            {
                name_tag: private_ip_address
                for ec2_client in ec2_clients
                for private_ip_address, name_tag in map(
                    partial(serialize_ec2_instance, tag_key), ec2_client.instances.all()
                )
                if name_tag
            }
        )
        time.sleep(update_interval)


def main(opts):
    logging.basicConfig(
        handlers=[logging.StreamHandler()],
        level=logging.INFO,
        format="%(asctime)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )

    hostmap = {}

    update_thread = Thread(
        target=hostmap_updater,
        args=(opts.aws_credentials_path, opts.tag, opts.update_interval, hostmap),
        daemon=True,
    )
    update_thread.start()

    factory = server.DNSServerFactory(
        caches=[
            cache.CacheResolver(),
        ],
        clients=[
            DynamicResolver(hostmap=hostmap, ttl=opts.ttl),
            client.Resolver(resolv="/etc/resolv.conf"),
        ],
    )

    protocol = dns.DNSDatagramProtocol(controller=factory)

    bind_host, bind_port = opts.bind.split(":")
    logging.info(f"Binding to {bind_host}:{bind_port}/udp")
    reactor.listenUDP(int(bind_port), protocol, interface=bind_host)
    logging.info(f"Binding to {bind_host}:{bind_port}/tcp")
    reactor.listenTCP(int(bind_port), factory, interface=bind_host)

    logging.info("Starting server...")
    reactor.run()


if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument(
        "--bind",
        type=str,
        default="127.0.0.1:53",
        help="binding address and port (both tcp/udp)",
    )
    arg_parser.add_argument(
        "--aws-credentials-path",
        type=str,
        default="./aws-credentials",
        help="",
    )
    arg_parser.add_argument(
        "--tag",
        type=str,
        default="Name",
        help="aws tag name to be matched by dns query",
    )
    arg_parser.add_argument(
        "--ttl",
        type=int,
        default=30,
        help="time the result will remain in cache, in seconds",
    )
    arg_parser.add_argument(
        "--update-interval",
        type=int,
        default=60,
        help="frequency of fetching querying ec2 for available hosts, in seconds",
    )

    opts = arg_parser.parse_args()

    main(opts)
