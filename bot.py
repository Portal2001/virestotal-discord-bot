import discord
import os
import requests

my_secret = os.environ['tocken']
my_secret1 = os.environ['key']

intents = discord.Intents.default()
intents.message_content = True

client = discord.Client(intents=intents)

# API endpoint for VirusTotal
url = 'https://www.virustotal.com/vtapi/v2/url/report'

# Your API key for VirusTotal
api_key = my_secret1


@client.event
async def on_message(message):
    # Check if the message contains a URL
    if message.content.startswith('http'):
        # Make the request to VirusTotal API
        params = {'apikey': api_key, 'resource': message.content}
        response = requests.get(url, params=params)
        json_response = response.json()

        # Check if the URL is malicious
        if json_response['positives'] > 0:
            # Delete the message if it contains a malicious URL
            await message.delete()

            # Send a message with the information from the API
            embed = discord.Embed(title="VirusTotal API Results", color=0xff0000)
            embed.add_field(name="URL", value=json_response['url'], inline=False)
            embed.add_field(name="Detection Ratio", value=str(json_response['positives']) + "/" + str(json_response['total']), inline=False)

            detected_by = [key for key, value in json_response['scans'].items() if value['detected']]
            if len(', '.join(detected_by)) > 1024:
                num_fields = len(detected_by) // 5 + 1
                for i in range(num_fields):
                    start = i * 5
                    end = (i + 1) * 5
                    if end > len(detected_by):
                        end = len(detected_by)
                    embed.add_field(name="Detected by", value=', '.join(detected_by[start:end]), inline=False)
            else:
                embed.add_field(name="Detected by", value=', '.join(detected_by), inline=False)

            await message.channel.send(embed=embed)

    # Check if the message contains a file attachment
    for attachment in message.attachments:
        # Make the request to VirusTotal API
        files = {'file': (attachment.filename, await attachment.read())}
        params = {'apikey': api_key}
        response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
        json_response = response.json()

        # Check if the file is malicious
        if json_response['response_code'] == 1 and json_response['positives'] > 0:
            # Delete the message if it contains a malicious file
            await message.delete()

            # Send a message with the information from the API
            embed = discord.Embed(title="VirusTotal API Results", color=0xff0000)
            embed.add_field(name="File Name", value=attachment.filename, inline=False)
            embed.add_field(name="Detection Ratio", value=str(json_response['positives']) + "/" + str(json_response['total']), inline=False)

            detected_by = [key for key, value in json_response['scans'].items() if value['detected']]
            if len(', '.join(detected_by)) > 1024:
                num_fields = len(detected_by) // 5 + 1
                for i in range(num_fields):
                    start = i * 5
                    end = (i + 1) * 5
                    if end > len(detected_by):
                        end = len(detected_by)
                    embed.add_field(name="Detected by", value=', '.join(detected_by[start:end]), inline=False)
            else:
                embed.add_field(name="Detected by", value=', '.join(detected_by), inline=False)

            await message.channel.send(embed=embed)


client.run(my_secret)
