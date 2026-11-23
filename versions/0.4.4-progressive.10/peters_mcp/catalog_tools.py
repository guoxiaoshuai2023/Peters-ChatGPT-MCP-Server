"""Shared MCP file tool declarations for the human and Agent endpoints."""

from mcp.types import ToolAnnotations

FILE_TOOLS = frozenset({'list_projects', 'list_worktrees', 'list_files', 'search', 'read_file'})


def register_catalog_tools(server, invoke, *, project_listing=None):
    annotations = ToolAnnotations(readOnlyHint=True, destructiveHint=False,
                                  idempotentHint=True, openWorldHint=False)

    def list_projects() -> dict:
        """List available project IDs and display names. Call this before reading files."""
        return invoke("list_projects")

    server.tool(name="list_projects", annotations=annotations)(project_listing or list_projects)

    @server.tool(annotations=annotations)
    def list_worktrees(project_id: str) -> dict:
        """Discover this authorized repository's registered working directories, including hidden/external ones.

        Match the user's branch/worktree to a valid entry, then pass its id as worktree_id
        to file tools. Entries include current branch/HEAD and unavailable states. No
        checkout/fetch/creation. The ID main means the configured default directory, not
        necessarily the Git branch named main. Invalid or undiscovered entries are not readable.
        """
        return invoke("list_worktrees", project_id=project_id)

    @server.tool(annotations=annotations)
    def list_files(project_id: str, directory: str = "", offset: int = 0, limit: int = 100, worktree_id: str = "") -> dict:
        """Browse one project-relative directory. Empty directory means root. Follow next_offset.

        Resolve worktree_id with list_worktrees. Unsupported files are labeled; hidden
        or Git-ignored ordinary files are not permission failures. Not a recursive tree.
        """
        return invoke("list_files", project_id=project_id, directory=directory, offset=offset, limit=limit, worktree_id=worktree_id)

    @server.tool(annotations=annotations)
    def search(project_id: str, query: str, directory: str = "", limit: int = 30,
               case_sensitive: bool = False, worktree_id: str = "", include_caches: bool = False) -> dict:
        """Recursively search literal text in one project, optionally within a directory.

        Returns paths, line numbers, snippets and file hashes. Not regex or semantic search.
        Resolve worktree_id using list_worktrees; nested repositories are not mixed in.
        Caches are directly readable but not indexed unless include_caches=true.
        Check complete, skipped and stopped_reason; narrow directory when coverage is limited.
        """
        return invoke("search", project_id=project_id, query=query, directory=directory,
                      limit=limit, case_sensitive=case_sensitive, worktree_id=worktree_id, include_caches=include_caches)

    @server.tool(annotations=annotations)
    def read_file(project_id: str, path: str, offset: int = 0, limit: int = 20000,
                  expected_sha256: str = "", worktree_id: str = "") -> dict:
        """Read a UTF-8 text/code file by project-relative path, at most 40,000 characters.

        Use list_worktrees to select a checked-out branch via worktree_id. Returned
        working_directory identifies the actual source; file SHA is independent of HEAD.
        Follow next_offset to continue. Pass the returned sha256 as expected_sha256 on
        subsequent reads to reject changed versions. Offsets count characters, not bytes.
        PDF, office, image and binary formats are unsupported. Maximum file size: 8 MiB.
        """
        return invoke("read_file", project_id=project_id, path=path, offset=offset,
                      limit=limit, expected_sha256=expected_sha256, worktree_id=worktree_id)
