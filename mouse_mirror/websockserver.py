# python3 -m pip install SimpleWebSocketServer
from SimpleWebSocketServer import SimpleWebSocketServer, WebSocket

clients = []
class SimpleServer(WebSocket):

    def handleMessage(self):
       for client in clients:
          if client != self:
             client.sendMessage(self.data)

    def handleConnected(self):
       print(self.address, 'connected')
       for client in clients:
          client.sendMessage(self.address[0] + u' - connected')
       clients.append(self)

    def handleClose(self):
       clients.remove(self)
       print(self.address, 'closed')
       for client in clients:
          client.sendMessage(self.address[0] + u' - disconnected')

server = SimpleWebSocketServer('127.0.0.1', 8000, SimpleServer)
print('WebSocket Server running on PORT 8000')
server.serveforever()