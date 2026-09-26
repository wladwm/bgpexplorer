#!/usr/bin/env python
# -*- coding: utf-8 -*-
import asyncio
import aiohttp
import json

# run the client
async def main():
    # start a session
    async with aiohttp.ClientSession() as session:
        # connect to the server
        async with session.ws_connect('http://127.0.0.1:8080/api/ws') as ws:
            # report progress
            print('Connected to server')
            # send the message to the server
            await ws.send_str(json.dumps({"Subscribe":{"rib": "ipv4u","filter":""}}))
            while True:
              # receive response
              result = await ws.receive()
              # report response
              if result.type == aiohttp.WSMsgType.TEXT:
                  print(f'Received: {result.data}')
              if result.type == aiohttp.WSMsgType.ERROR:
                  break
    # report progress
    print('Disconnected')

# start the event loop
asyncio.run(main())