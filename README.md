# ACME v2 client library in go

This is a work in progress library for fetching TLS certs from Let's Encrypt in go based on a previous project that
really only worked as a standalone client.   The previous project was tightly coupled to AWS for both handling
the DNS challenges and for storing the keys & certs, this aims to decouple that by just taking simple interfaces that
set and remove a TXT record from DNS and store/retrieve key and cert pairs.   That said, if you're using Route53 for
your DNS and are okay with storing the keys and certs in AWS Secrets Manager, then that part's pretty much already 
taken care of.

