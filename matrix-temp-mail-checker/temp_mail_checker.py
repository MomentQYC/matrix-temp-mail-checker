from typing import Collection, Optional, Tuple
from synapse.spam_checker_api import RegistrationBehaviour
import logging

logger = logging.getLogger(__name__)


class TempMailChecker:

    @staticmethod
    def parse_config(config) -> dict:
        return config

    def __init__(self, config: dict, api):
        self.api = api
        api.register_spam_checker_callbacks(check_registration_for_spam=self.check_registration_for_spam)
        with open(config["blocked_domains_file"], "r") as f:
            self.blocked_domains = {line.strip().lower() for line in f if line.strip()}
        logger.info(f"Loaded {len(self.blocked_domains)} blocked domains.")

    async def check_registration_for_spam(
        self,
        email_threepid: Optional[dict],
        username: Optional[str],
        request_info: Collection[Tuple[str, str]],
        auth_provider_id: Optional[str] = None,
    ):
        if email_threepid:
            try:
                domain: str = email_threepid["address"].split("@")[-1].lower()
            except Exception:
                logger.critical(f"Wrong email_threepid: {type(email_threepid)} : {email_threepid}")
                return RegistrationBehaviour.DENY
            if domain in self.blocked_domains:
                logger.warning(f"Blocked registration attempt for email domain: {domain}")
                return RegistrationBehaviour.DENY
        return RegistrationBehaviour.ALLOW
