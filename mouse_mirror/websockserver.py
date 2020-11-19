# python3 -m pip install SimpleWebSocketServer
import sys, datetime
from SimpleWebSocketServer import SimpleWebSocketServer, WebSocket

if len(sys.argv) < 3:
   print(f'[!] Usage: {sys.argv[0]} IP PORT [-v]')
   exit()

IP, PORT = [sys.argv[1], int(sys.argv[2])]

clients = []
class SimpleServer(WebSocket):

    def handleMessage(self):
       for client in clients:
          if client != self:
             if len(sys.argv) == 4:
               print(f'[{datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}] {self.address[0]} : {self.data}')
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

server = SimpleWebSocketServer(IP, int(PORT), SimpleServer)
print(f'WebSocket Server running on PORT http://{IP}:{PORT}')
server.serveforever()
