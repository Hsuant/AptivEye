"""Centralized configuration via pydantic-settings.

All settings are loaded from environment variables with .env file support.
Sensitive values (API keys) are never hardcoded.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _project_root() -> Path:
    """Resolve project root relative to this config file."""
    return Path(__file__).resolve().parent.parent


class LLMSettings(BaseSettings):
    """LLM provider configuration."""

    model_config = SettingsConfigDict(env_prefix="", env_file=".env", extra="ignore")

    openai_api_key: SecretStr = Field(default=SecretStr(""), alias="OPENAI_API_KEY")
    openai_base_url: str = Field(default="https://api.openai.com/v1", alias="OPENAI_BASE_URL")
    anthropic_api_key: SecretStr = Field(default=SecretStr(""), alias="ANTHROPIC_API_KEY")
    ollama_base_url: str = Field(default="http://localhost:11434", alias="OLLAMA_BASE_URL")
    deepseek_api_key: SecretStr = Field(default=SecretStr(""), alias="DEEPSEEK_API_KEY")
    deepseek_base_url: str = Field(default="https://api.deepseek.com/v1", alias="DEEPSEEK_BASE_URL")

    # Model tier assignments
    light_model: str = Field(default="gpt-4o-mini", alias="LIGHT_MODEL")
    standard_model: str = Field(default="gpt-4o", alias="STANDARD_MODEL")
    heavy_model: str = Field(default="gpt-4o", alias="HEAVY_MODEL")

    # Local model
    local_model_enabled: bool = Field(default=False, alias="LOCAL_MODEL_ENABLED")
    local_model_name: str = Field(default="llama3.1:8b", alias="LOCAL_MODEL_NAME")

    @field_validator("openai_api_key", mode="before")
    @classmethod
    def _warn_missing_openai(cls, v: str) -> str:
        if not v:
            import warnings

            warnings.warn("OPENAI_API_KEY is not set — OpenAI models will be unavailable.", stacklevel=2)
        return v

    @field_validator("anthropic_api_key", mode="before")
    @classmethod
    def _warn_missing_anthropic(cls, v: str) -> str:
        if not v:
            import warnings

            warnings.warn(
                "ANTHROPIC_API_KEY is not set — Claude models will be unavailable.", stacklevel=2
            )
        return v

    @field_validator("deepseek_api_key", mode="before")
    @classmethod
    def _warn_missing_deepseek(cls, v: str) -> str:
        if not v:
            import warnings

            warnings.warn(
                "DEEPSEEK_API_KEY is not set — DeepSeek models will be unavailable.", stacklevel=2
            )
        return v


class SandboxSettings(BaseSettings):
    """Docker sandbox configuration."""

    model_config = SettingsConfigDict(env_prefix="SANDBOX_", env_file=".env", extra="ignore")

    enabled: bool = False
    image: str = "aptiveye-sandbox:latest"
    network_mode: str = "none"
    timeout_seconds: int = 300


class MemorySettings(BaseSettings):
    """Vector store and memory configuration."""

    model_config = SettingsConfigDict(env_prefix="", env_file=".env", extra="ignore")

    vector_store_type: Literal["chroma", "qdrant"] = Field(
        default="chroma", alias="VECTOR_STORE_TYPE"
    )
    vector_store_path: str = Field(default="./data/vector_store", alias="VECTOR_STORE_PATH")
    chroma_persist_dir: str = Field(default="./data/chroma", alias="CHROMA_PERSIST_DIR")


class AssetAPISettings(BaseSettings):
    """Third-party API keys and endpoint URLs for extended asset discovery.

    Every API endpoint URL is independently configurable, enabling:
      - Self-hosted / mirrored API instances
      - Custom API gateways / proxies
      - Air-gapped environments with local replicas
    """

    model_config = SettingsConfigDict(env_prefix="", env_file=".env", extra="ignore")

    # ── FOFA (https://fofa.info) ──
    fofa_email: str = Field(default="", alias="FOFA_EMAIL")
    fofa_api_key: SecretStr = Field(default=SecretStr(""), alias="FOFA_API_KEY")
    fofa_api_url: str = Field(default="https://fofa.info/api/v1", alias="FOFA_API_URL")
    fofa_web_url: str = Field(default="https://fofa.info", alias="FOFA_WEB_URL")

    # ── ZoomEye (https://zoomeye.org) ──
    zoomeye_api_key: SecretStr = Field(default=SecretStr(""), alias="ZOOMEYE_API_KEY")
    zoomeye_api_url: str = Field(default="https://api.zoomeye.org", alias="ZOOMEYE_API_URL")
    zoomeye_web_url: str = Field(default="https://www.zoomeye.org", alias="ZOOMEYE_WEB_URL")

    # ── ICP备案 ──
    icp_api_key: SecretStr = Field(default=SecretStr(""), alias="ICP_API_KEY")
    icp_api_url: str = Field(default="https://api.beian.miit.gov.cn", alias="ICP_API_URL")
    icp_public_url: str = Field(
        default="https://api.devopsclub.cn/api/icpquery", alias="ICP_PUBLIC_URL"
    )

    # ── 企查查 ──
    qichacha_api_key: SecretStr = Field(default=SecretStr(""), alias="QICHACHA_API_KEY")
    qichacha_api_url: str = Field(
        default="https://api.qichacha.com", alias="QICHACHA_API_URL"
    )

    # ── 天眼查 ──
    tianyancha_api_key: SecretStr = Field(default=SecretStr(""), alias="TIANYANCHA_API_KEY")
    tianyancha_api_url: str = Field(
        default="https://api.tianyancha.com", alias="TIANYANCHA_API_URL"
    )

    # ── 零零信安 ──
    lingling_api_key: SecretStr = Field(default=SecretStr(""), alias="LINGLING_API_KEY")
    lingling_api_url: str = Field(
        default="https://api.0zero.cn", alias="LINGLING_API_URL"
    )

    # ── Hunter.io (email discovery) ──
    hunter_api_key: SecretStr = Field(default=SecretStr(""), alias="HUNTER_API_KEY")
    hunter_api_url: str = Field(
        default="https://api.hunter.io/v2", alias="HUNTER_API_URL"
    )

    # ── crt.sh (certificate transparency) ──
    crtsh_api_url: str = Field(
        default="https://crt.sh", alias="CRTSH_API_URL"
    )

    # ── 搜狗微信搜索 ──
    weixin_search_url: str = Field(
        default="https://weixin.sogou.com/weixin", alias="WEIXIN_SEARCH_URL"
    )

    # ── 微信小程序搜索 ──
    miniprogram_search_url: str = Field(
        default="https://mp.weixin.qq.com/wxamp/search", alias="MINIPROGRAM_SEARCH_URL"
    )

    # ── iTunes App Store ──
    itunes_search_url: str = Field(
        default="https://itunes.apple.com/search", alias="ITUNES_SEARCH_URL"
    )


class AgentSettings(BaseSettings):
    """Agent runtime configuration."""

    model_config = SettingsConfigDict(env_prefix="AGENT_", env_file=".env", extra="ignore")

    max_iterations: int = 20
    timeout_seconds: int = 600
    max_workers: int = 5


class SecuritySettings(BaseSettings):
    """Security-related configuration."""

    model_config = SettingsConfigDict(env_prefix="", env_file=".env", extra="ignore")

    loop_detection_threshold: int = Field(default=3, alias="LOOP_DETECTION_THRESHOLD")
    hitl_enabled: bool = Field(default=True, alias="HITL_ENABLED")
    audit_log_path: str = Field(default="./data/audit", alias="AUDIT_LOG_PATH")


class LoggingSettings(BaseSettings):
    """Logging configuration."""

    model_config = SettingsConfigDict(env_prefix="", env_file=".env", extra="ignore")

    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    log_file: str = Field(default="./data/logs/aptiveye.log", alias="LOG_FILE")


class ReportSettings(BaseSettings):
    """Report output configuration."""

    model_config = SettingsConfigDict(env_prefix="", env_file=".env", extra="ignore")

    output_dir: str = Field(default="./data/reports", alias="REPORT_OUTPUT_DIR")


class Settings(BaseSettings):
    """Top-level settings aggregating all sub-configs."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    llm: LLMSettings = Field(default_factory=LLMSettings)
    sandbox: SandboxSettings = Field(default_factory=SandboxSettings)
    memory: MemorySettings = Field(default_factory=MemorySettings)
    agent: AgentSettings = Field(default_factory=AgentSettings)
    security: SecuritySettings = Field(default_factory=SecuritySettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)
    report: ReportSettings = Field(default_factory=ReportSettings)
    asset_api: AssetAPISettings = Field(default_factory=AssetAPISettings)

    # Derived paths
    @property
    def project_root(self) -> Path:
        return _project_root()

    @property
    def data_dir(self) -> Path:
        return self.project_root / "data"

    def ensure_directories(self) -> None:
        """Create all required data directories."""
        dirs = [
            self.data_dir / "cve",
            self.data_dir / "vector_store",
            self.data_dir / "reports",
            self.data_dir / "audit",
            self.data_dir / "logs",
        ]
        for d in dirs:
            d.mkdir(parents=True, exist_ok=True)


@lru_cache()
def get_settings() -> Settings:
    """Return cached singleton Settings instance."""
    return Settings()


# ---------------------------------------------------------------------------
# Prompt paths helper
# ---------------------------------------------------------------------------
PROMPTS_DIR = _project_root() / "config" / "prompts"

# Ensure prompts directory exists
PROMPTS_DIR.mkdir(parents=True, exist_ok=True)
