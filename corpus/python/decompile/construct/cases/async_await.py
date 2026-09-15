async def f(client):
    token = await client.authenticate()
    data = await client.read(token)
    return data
