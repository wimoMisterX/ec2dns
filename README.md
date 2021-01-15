# aws-ec2-dns - DNS naming for your EC2 instances

`aws-ec2-dns` is a DNS server that lets you discover EC2 instances by a name you assign them (via tags).

How does it work?

* Add a tag (or by default we use the `Name` tag) to the EC2 instances you want to give a name. The value of this tag will become the DNS name of the instance.
* Run `aws-ec2-dns` as a local DNS server and configure it as your DNS server.
* Look up any EC2 instance by using the name you assigned.

## Running `aws-ec2-dns`

Make sure your EC2 instances have a tag that you can use to refer to them (for example, you can use the tag `aws-ec2-dns`), set a value like `mailserver`.

`aws-ec2-dns` accepts the following configuration parameters:

* `--bind=ipaddress:port`: binding address and port. Sets both TCP and UDP. By default, `127.0.0.1:53`. Please note that you will need to be root to be able to access port 53.
* `--ttl=seconds`: time that the results will remain in cache, in seconds. This value is used for the TTL in the answers, so clients can cache them, and also internally for caching the responses given by AWS. By default, `30`.
* `--tag=tagname`: tag name in EC2 that contains the DNS name. By default, `Name`.
