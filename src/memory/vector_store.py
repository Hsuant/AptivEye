"""Vector store abstraction over Chroma / Qdrant.

Provides a unified interface for embedding-based retrieval.
Used by: CVE knowledge base, session memory, tool documentation.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Sequence

from config.settings import get_settings
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class Document:
    """A document stored in the vector database."""

    id: str
    content: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class SearchResult:
    """A single search result with relevance score."""

    document: Document
    score: float  # 0-1, higher = more relevant


class BaseVectorStore(ABC):
    """Abstract interface for vector store operations."""

    @abstractmethod
    async def add(self, documents: list[Document]) -> None:
        """Add documents to the store (with embeddings)."""
        ...

    @abstractmethod
    async def search(
        self,
        query: str,
        *,
        top_k: int = 5,
        filter_metadata: dict[str, Any] | None = None,
    ) -> list[SearchResult]:
        """Semantic search with optional metadata filtering."""
        ...

    @abstractmethod
    async def delete(self, ids: list[str]) -> None:
        """Remove documents by ID."""
        ...

    @abstractmethod
    async def count(self) -> int:
        """Return the total number of documents."""
        ...


class ChromaVectorStore(BaseVectorStore):
    """ChromaDB-backed vector store (development default)."""

    def __init__(self, persist_dir: str | None = None) -> None:
        try:
            import chromadb
        except ImportError:
            raise ImportError(
                "chromadb is required. Install with: pip install chromadb"
            )

        settings = get_settings().memory
        persist_dir = persist_dir or settings.chroma_persist_dir

        self._client = chromadb.PersistentClient(path=persist_dir)
        self._collection = self._client.get_or_create_collection(
            name="aptiveye_knowledge",
            metadata={"hnsw:space": "cosine"},
        )
        logger.info("ChromaDB initialized at {}", persist_dir)

    async def add(self, documents: list[Document]) -> None:
        if not documents:
            return

        ids = [d.id for d in documents]
        contents = [d.content for d in documents]
        metadatas = [d.metadata for d in documents]

        # Chroma handles embedding automatically with its default function
        self._collection.add(
            ids=ids,
            documents=contents,
            metadatas=metadatas,
        )
        logger.debug("Added {} documents to ChromaDB", len(documents))

    async def search(
        self,
        query: str,
        *,
        top_k: int = 5,
        filter_metadata: dict[str, Any] | None = None,
    ) -> list[SearchResult]:
        where_filter = filter_metadata or None
        results = self._collection.query(
            query_texts=[query],
            n_results=top_k,
            where=where_filter,
        )

        search_results: list[SearchResult] = []
        ids_list = results.get("ids", [[]])[0]
        docs_list = results.get("documents", [[]])[0]
        metas_list = results.get("metadatas", [[]])[0]
        distances = results.get("distances", [[]])[0]

        for i, doc_id in enumerate(ids_list):
            # Convert cosine distance to similarity score
            distance = distances[i] if i < len(distances) else 0.0
            score = 1.0 - min(distance, 1.0)

            search_results.append(SearchResult(
                document=Document(
                    id=doc_id,
                    content=docs_list[i] if i < len(docs_list) else "",
                    metadata=metas_list[i] if i < len(metas_list) else {},
                ),
                score=score,
            ))

        return search_results

    async def delete(self, ids: list[str]) -> None:
        if ids:
            self._collection.delete(ids=ids)
            logger.debug("Deleted {} documents from ChromaDB", len(ids))

    async def count(self) -> int:
        return self._collection.count()


class NoOpVectorStore(BaseVectorStore):
    """Fallback when no vector store is configured."""

    async def add(self, documents: list[Document]) -> None:
        logger.debug("NoOpVectorStore: add({} docs) — no-op", len(documents))

    async def search(
        self,
        query: str,
        *,
        top_k: int = 5,
        filter_metadata: dict[str, Any] | None = None,
    ) -> list[SearchResult]:
        logger.debug("NoOpVectorStore: search({}) — returning empty", query[:50])
        return []

    async def delete(self, ids: list[str]) -> None:
        pass

    async def count(self) -> int:
        return 0


def create_vector_store() -> BaseVectorStore:
    """Factory: return the configured vector store implementation."""
    settings = get_settings().memory

    if settings.vector_store_type == "chroma":
        try:
            return ChromaVectorStore()
        except ImportError as e:
            logger.warning("ChromaDB not available ({}), using no-op store", e)
            return NoOpVectorStore()
    elif settings.vector_store_type == "qdrant":
        logger.warning("Qdrant support — Phase 5. Using no-op store.")
        return NoOpVectorStore()
    else:
        logger.warning("Unknown vector store type '{}', using no-op", settings.vector_store_type)
        return NoOpVectorStore()
