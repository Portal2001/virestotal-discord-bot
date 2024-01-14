import discord
import os
import aiohttp
import asyncio
import re

my_secret = os.environ['token']
my_secret1 = os.environ['key']

intents = discord.Intents.default()
intents.message_content = True
intents.messages = True

client = discord.Client(intents=intents)

url = 'https://www.virustotal.com/api/v3'

api_key = my_secret1


# extract URLs from a message
def find_urls_in_message(message_content):
  url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
  return re.findall(url_pattern, message_content)


async def check_url(session, message, url_to_check):
  async with session.post(url + '/urls',
                          headers={'x-apikey': api_key},
                          data={'url': url_to_check}) as response:
    json_response = await response.json()

    url_id = json_response['data']['id']

  # Wait for the analysis to complete
  analysis_complete = False
  while not analysis_complete:
    async with session.get(url + f'/analyses/{url_id}',
                           headers={'x-apikey': api_key}) as response:
      json_response = await response.json()
      status = json_response.get('data', {}).get('attributes',
                                                 {}).get('status')
      if status == 'completed':
        analysis_complete = True
      else:
        await asyncio.sleep(5)  

  # Process the results
  stats = json_response.get('data', {}).get('attributes', {}).get('stats', {})
  if stats.get('malicious', 0) > 0:
    try:
      await message.delete()
    except discord.errors.NotFound:
      pass

    embed = discord.Embed(title="VirusTotal API Results", color=0xff0000)
    embed.add_field(name="URL", value=url_to_check, inline=False)
    total_checks = sum(stats.values())

    embed.add_field(name="Detection Ratio",
                    value=f"{stats.get('malicious', 0)}/{total_checks}")
    await message.channel.send(embed=embed)
  else:
    embed = discord.Embed(title="URL Analysis Results",
                          description="The URL is clean.",
                          color=0x00ff00)
    embed.add_field(name="URL", value=url_to_check, inline=False)
    await message.channel.send(embed=embed)


async def check_file(session, message, attachment):
  data = aiohttp.FormData()
  data.add_field('file', await attachment.read(), filename=attachment.filename)
  async with session.post(url + '/files',
                          headers={'x-apikey': api_key},
                          data=data) as response:
    json_response = await response.json()
  file_id = json_response['data']['id']


  analysis_complete = False
  while not analysis_complete:
    async with session.get(url + f'/analyses/{file_id}',
                           headers={'x-apikey': api_key}) as response:
      json_response = await response.json()
      status = json_response.get('data', {}).get('attributes',
                                                 {}).get('status')
      if status == 'completed':
        analysis_complete = True
      else:
        await asyncio.sleep(5)  

  stats = json_response.get('data', {}).get('attributes', {}).get('stats', {})
  if stats.get('malicious', 0) > 0:
    await message.delete()
    embed = discord.Embed(title="File Analysis Results",
                          description="Malicious file detected and removed.",
                          color=0xff0000)
    embed.add_field(name="File Name", value=attachment.filename, inline=False)

    total_checks = sum(stats.values())

    embed.add_field(name="Detection Ratio",
                    value=f"{stats.get('malicious', 0)}/{total_checks}")
    await message.channel.send(embed=embed)


@client.event
async def on_message(message):
  if message.author == client.user:
    return

  async with aiohttp.ClientSession() as session:
    urls = find_urls_in_message(message.content)
    for url_to_check in urls:
      await check_url(session, message, url_to_check)
    for attachment in message.attachments:
      await check_file(session, message, attachment)


if __name__ == "__main__":
  client.run(my_secret)
