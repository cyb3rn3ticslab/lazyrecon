#!/bin/bash
# send report using discord webhook

# https://www.digitalocean.com/community/tutorials/how-to-use-discord-webhooks-to-get-notifications-for-your-website-status-on-ubuntu-18-04#:~:text=To%20create%20a%20webhook%20you,click%20the%20Create%20Webhook%20button.
# https://discord.com/developers/docs/resources/webhook


file="$@"
curl -v -H "Content-Type: multipart/form-data" -X POST -F file=@$file $DISCORDWEBHOOKURL
