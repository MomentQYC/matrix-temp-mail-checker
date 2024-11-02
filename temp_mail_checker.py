from synapse.spam_checker_api import RegistrationBehaviour
import logging

logger = logging.getLogger(__name__)

class TempMailChecker:
    def __init__(self, config, api):
        self.api = api
        self.api.register_spam_checker_callbacks(
            check_registration_for_spam=self.check_registration_for_spam
        )
        self.blocked_domains = self._load_blocked_domains(config.get("blocked_domains_file"))

    @staticmethod
    def parse_config(config):
        return config

    def _load_blocked_domains(self, file_path):
        try:
            with open(file_path, "r") as f:
                domains = {line.strip().lower() for line in f if line.strip()}
            logger.info(f"Loaded {len(domains)} blocked domains.")
            return domains
        except Exception as e:
            logger.error(f"Failed to load blocked domains file: {e}")
            return set()

    async def check_registration_for_spam(
        self, email_threepid, username, request_info, auth_provider_id=None
    ):
        if email_threepid:
            domain = email_threepid.get("address").split('@')[-1].lower()
            if domain in self.blocked_domains:
                logger.warning(f"Blocked registration attempt for email domain: {domain}")
                return RegistrationBehaviour.DENY
        return RegistrationBehaviour.ALLOW
