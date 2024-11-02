from typing import Collection, Optional, Tuple
from synapse.spam_checker_api import RegistrationBehaviour
from synapse.module_api import ModuleApi

import logging

logger = logging.getLogger(__name__)


class TempMailChecker:

    @staticmethod
    def parse_config(config) -> dict:
        return config

    def __init__(self, config: dict, api: ModuleApi):
        self.api = api
        api.register_spam_checker_callbacks(check_registration_for_spam=self.check_registration_for_spam)
        self.blocked_domains_file = config["blocked_domains_file"]

    def _load_blocked_domains(self):
        with open(self.blocked_domains_file, "r") as f:
            domains = {line.strip().lower() for line in f if line.strip()}
        logger.info(f"Loaded {len(domains)} blocked domains.")
        return domains

    async def check_registration_for_spam(
        self,
        email_threepid: Optional[dict],
        username: Optional[str],
        request_info: Collection[Tuple[str, str]],
        auth_provider_id: Optional[str] = None,
    ):
        self.blocked_domains = self._load_blocked_domains()

        if email_threepid:
            try:
                domain: str = email_threepid["address"].split("@")[-1].lower()
            except Exception:
                logger.critical(f"Wrong email_threepid: {type(email_threepid)} : {email_threepid}")
                return RegistrationBehaviour.ALLOW
            if domain in self.blocked_domains:
                logger.warning(f"Blocked registration attempt for email domain: {domain}")
                return RegistrationBehaviour.DENY
        return RegistrationBehaviour.ALLOW
