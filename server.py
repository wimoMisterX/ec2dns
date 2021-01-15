from twisted.internet import reactor, defer
from twisted.names import client, dns, error, server


def handle_aws_dns_request(query):
    pass


def is_resolvable(query):
    pass


class DynamicResolver(object):
    def query(self, query, timeout=None):
        if is_resolvable(query):
            return defer.succeed(handle_aws_dns_request(query))
        return defer.fail(error.DomainError())


def main():
    factory = server.DNSServerFactory(
        clients=[DynamicResolver(), client.Resolver(resolv="/etc/resolv.conf")],
    )

    protocol = dns.DNSDatagramProtocol(controller=factory)

    reactor.listenUDP(53, protocol)
    reactor.listenTCP(53, factory)

    reactor.run()


if __name__ == "__main__":
    raise SystemExit(main())
