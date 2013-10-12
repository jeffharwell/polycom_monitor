#!/usr/bin/python2

"""
This is the server program. It listens for the status of the client,
passes commands, receives results, and makes the results available 
through an API
"""

from twisted.web import xmlrpc, server

class ClientInterface(xmlrpc.XMLRPC):
    def xmlrpc_clientCheckIn(self, client_id, status):
        """
        Method that the clients call to check in, share their status, and get commands
        """
        print "Client: %s Status: %s" % (client_id, status)

        return ("sleep",30)

if __name__ == '__main__':
    from twisted.internet import reactor
    ci = ClientInterface()
    reactor.listenTCP(7080, server.Site(ci))
    reactor.run()
