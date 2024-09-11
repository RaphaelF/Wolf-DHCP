# DHCP

This is a simple DHCP server.

## Modular Architecture

Extensions to the supported options can be made by including modules that implement the extensions and register themselves (for example, see .v4.rfc4578)

## Running

To run a basic DHCPv4 server which serves addresses between 10.0.0.2 and 10.0.0.254, simply run the server as `python3 -m dhcp.v4.server`

To run a PXE server for network booting, you can use `python3 -m dhcp.pxe --help` to see the options for running a PXE boot server.

DHCPv6 is currently unsupported.

## Standards

This is a standards-compliant DHCP server, implementing the following RFCs:

in .v4:
- [RFC2131](https://www.ietf.org/rfc/rfc2131.txt) for the base DHCPv4 spec
- [RFC2132](https://www.ietf.org/rfc/rfc2132.txt) for the base DHCPv4 options
- [RFC3396](https://www.ietf.org/rfc/rfc3396.txt) for encoding long DHCPv4 options
- [RFC4361](https://www.ietf.org/rfc/rfc4361.txt) for interoperable client identifiers
- [RFC6842](https://www.ietf.org/rfc/rfc6842.txt) for the client identifer option

for DHCPv4 PXE (also in .v4):
- [RFC3004](https://www.ietf.org/rfc/rfc3004.txt) for the DHCPv4 user class option
- [RFC4578](https://www.ietf.org/rfc/rfc4578.txt) for the DHCPv4 PXE options

in .v6
- [RFC8415](https://www.ietf.org/rfc/rfc8415.txt) for a unified DHCPv6 spec

in .tftp
- [RFC1350](https://www.ietf.org/rfc/rfc1350.txt) for the base TFTP spec
- [RFC1782](https://www.ietf.org/rfc/rfc1782.txt) for TFTP options
- [RFC1783](https://www.ietf.org/rfc/rfc1783.txt) for the TFTP blocksize option
- [RFC1784](https://www.ietf.org/rfc/rfc1784.txt) for the TFTP timeout and transfer size options
- [RFC7440](https://www.ietf.org/rfc/rfc7440.txt) for the TFTP windowsize option

