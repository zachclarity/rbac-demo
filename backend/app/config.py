"""Application configuration from environment variables."""
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql+asyncpg://appuser:apppass@localhost:5433/securedata"
    DATABASE_URL_SYNC: str = "postgresql://appuser:apppass@localhost:5433/securedata"
    KEYCLOAK_URL: str = "http://localhost:8080"
    KEYCLOAK_REALM: str = "agency-alpha"
    KEYCLOAK_CLIENT_ID: str = "backend-api"
    CORS_ORIGINS: str = "http://localhost:3000"

    @property
    def keycloak_issuer(self) -> str:
        return f"{self.KEYCLOAK_URL}/realms/{self.KEYCLOAK_REALM}"

    @property
    def keycloak_jwks_url(self) -> str:
        return f"{self.keycloak_issuer}/protocol/openid-connect/certs"

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",")]


settings = Settings()
