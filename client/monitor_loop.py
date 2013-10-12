#!/usr/bin/python2

"""
Polycom Monitor Client

This is the Twisted Reactor code that checks in periodically with the 
server, gets orders, executes the orders, and then returns the results
"""

from twisted.web.xmlrpc import Proxy
from twisted.internet import reactor

class Report:
    def __init__(self, client_id, proxy):
        self.proxy = proxy
        self.client_id = client_id
    def reportReady(self, a = 0):
	print "Reporting Status Ready: a = %s" % a
        self.proxy.callRemote('clientCheckIn',1,'ready').addCallbacks(self.processCommand)
    def sleep(self, secs):
        #d = defer.Deferred()
        #reactor.callLater(secs, d.callback, None)
        #return d
        print "Sleeping for %s seconds" % secs
        reactor.callLater(secs, self.reportReady, None)
    def processCommand(self, cmd):
	print "Received: %s" % cmd
        if cmd[0] == 'sleep':
            self.sleep(cmd[1])
        else:
            print "Unknown Command"

if __name__ == '__main__':
    proxy = Proxy('http://fox.fuller.edu:7080/XMLRPC')
    client_id = 1

    r = Report(client_id, proxy)
    r.reportReady()

    reactor.run()
