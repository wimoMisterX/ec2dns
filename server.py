import argparse
import boto3
import re
import json

from twisted.internet import reactor, defer
from twisted.names import client, cache, dns, error, server


class DynamicResolver(object):
    def __init__(self, aws_credentials_path, aws_tag, regexes, ttl=30):
        self.aws_tag = aws_tag
        self.regexes = [re.compile(regex) for regex in regexes]
        with open(aws_credentials_path, "rb") as fh:
            self.ec2_clients = [
                boto3.session.Session(
                    aws_access_key_id=credentials["aws_access_key_id"],
                    aws_secret_access_key=credentials["aws_secret_access_key"],
                    region_name=credentials["aws_region"],
                ).resource("ec2")
                for credentials in json.loads(fh.read())
            ]
        self.ttl = ttl

    def _is_resolvable(self, query):
        if query.type == dns.A:
            hostname = query.name.name.decode()
            return any(regex.match(hostname) for regex in self.regexes)
        return False

    def _handle_dns_query(self, query):
        ec2_filters = [
            {"Name": f"tag:{self.aws_tag}", "Values": [query.name.name.decode()]}
        ]
        answers = [
            dns.RRHeader(
                name=query.name.name,
                payload=dns.Record_A(
                    address=next(
                        ec2_instance.private_ip_address
                        for ec2_client in self.ec2_clients
                        for ec2_instance in ec2_client.instances.filter(
                            Filters=ec2_filters
                        )
                    )
                ),
                ttl=self.ttl,
            )
        ]
        authority = []
        additional = []
        return answers, authority, additional

    def query(self, query, timeout=None):
        print(f"Recieved {query.name.name.decode()}")
        if self._is_resolvable(query):
            print(f"{query.name.name.decode()} is resolvable")
            return defer.succeed(self._handle_dns_query(query))
        return defer.fail(error.DomainError())


def main(opts):
    factory = server.DNSServerFactory(
        caches=[
            cache.CacheResolver(),
        ],
        clients=[
            DynamicResolver(
                aws_credentials_path=opts.aws_credentials_path,
                aws_tag=opts.tag,
                ttl=opts.ttl,
                regexes=opts.match,
            ),
            client.Resolver(resolv="/etc/resolv.conf"),
        ],
    )

    protocol = dns.DNSDatagramProtocol(controller=factory)

    bind_host, bind_port = opts.bind.split(":")
    reactor.listenUDP(int(bind_port), protocol, interface=bind_host)
    reactor.listenTCP(int(bind_port), factory, interface=bind_host)

    print("Starting server...")
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
        "--match",
        nargs="+",
        default=[],
        help="regexs to resolve, if fails regex then default resolver is used",
    )

    opts = arg_parser.parse_args()

    main(opts)
