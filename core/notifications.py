import aiohttp
import logging
import json
import asyncio
logger = logging.getLogger("bb-recon")

class NotificationDispatcher:
    def __init__(self, config=None):
        self.config = config or {}
        self.min_severity = self.config.get("min_severity", "HIGH")
        self._severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    def _should_notify(self, severity):
        return self._severity_order.get(severity, 4) <= self._severity_order.get(self.min_severity, 1)

    async def notify(self, finding):
        severity = finding.get("severity", finding.get("type", "INFO"))
        if not self._should_notify(severity):
            return

        title = f"[{severity}] {finding.get('type', 'Finding')}"
        url = finding.get("url", "")
        param = finding.get("param", "")
        evidence = finding.get("evidence", finding.get("payload", ""))[:200]
        message = f"**{title}**\nURL: `{url}`"
        if param:
            message += f"\nParam: `{param}`"
        if evidence:
            message += f"\nEvidence: `{evidence}`"

        tasks = []
        if self.config.get("slack_webhook"):
            tasks.append(self._send_slack(message))
        if self.config.get("discord_webhook"):
            tasks.append(self._send_discord(message))
        if self.config.get("telegram_bot_token") and self.config.get("telegram_chat_id"):
            tasks.append(self._send_telegram(message))
        if self.config.get("custom_webhook"):
            tasks.append(self._send_custom(finding))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _send_slack(self, message):
        try:
            async with aiohttp.ClientSession() as s:
                payload = {"text": message.replace("**", "*").replace("`", "`")}
                await s.post(self.config["slack_webhook"], json=payload, timeout=aiohttp.ClientTimeout(total=5))
        except Exception as e:
            logger.debug(f"Slack notification failed: {e}")

    async def _send_discord(self, message):
        try:
            async with aiohttp.ClientSession() as s:
                payload = {"content": message}
                await s.post(self.config["discord_webhook"], json=payload, timeout=aiohttp.ClientTimeout(total=5))
        except Exception as e:
            logger.debug(f"Discord notification failed: {e}")

    async def _send_telegram(self, message):
        try:
            async with aiohttp.ClientSession() as s:
                bot_token = self.config["telegram_bot_token"]
                chat_id = self.config["telegram_chat_id"]
                api_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
                payload = {"chat_id": chat_id, "text": message, "parse_mode": "Markdown"}
                await s.post(api_url, json=payload, timeout=aiohttp.ClientTimeout(total=5))
        except Exception as e:
            logger.debug(f"Telegram notification failed: {e}")

    async def _send_custom(self, finding):
        try:
            async with aiohttp.ClientSession() as s:
                await s.post(self.config["custom_webhook"], json=finding, timeout=aiohttp.ClientTimeout(total=5))
        except Exception as e:
            logger.debug(f"Custom webhook notification failed: {e}")

    async def notify_scan_complete(self, domain, summary):
        message = f"**BB-RECON Scan Complete**\nTarget: `{domain}`\n"
        for k, v in summary.items():
            if isinstance(v, (int, float)) and v > 0:
                message += f"{k}: **{v}**\n"

        tasks = []
        if self.config.get("slack_webhook"):
            tasks.append(self._send_slack(message))
        if self.config.get("discord_webhook"):
            tasks.append(self._send_discord(message))
        if self.config.get("telegram_bot_token") and self.config.get("telegram_chat_id"):
            tasks.append(self._send_telegram(message))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

NOTIFIER = NotificationDispatcher()

def configure_notifications(config):
    global NOTIFIER
    NOTIFIER = NotificationDispatcher(config)
