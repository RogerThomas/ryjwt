// Adds a "Copy for uv" button above each code block tagged with a `data-uv-extra` attribute (the
// tabbed msgspec, pydantic and dict examples, e.g. docs/index.md's "A first token"). It copies a
// `uv run` command that runs that exact snippet, with nothing installed beforehand:
//
//     uv run --prerelease allow --with 'ryjwt[msgspec]' python - <<'PYEOF'
//     ...the snippet...
//     PYEOF
//
// `data-uv-extra` names the extra the snippet needs (`msgspec` or `pydantic`), or is empty for
// plain `ryjwt`. ryjwt is an alpha, so `--prerelease allow` lets uv pick a pre-release.
// tests/test_docs.py checks every tagged block names a real extra, and runs it.
//
// The button is our own, inserted just above the block, rather than added to Zensical's copy
// button bar: that bar is built in the browser, so its markup isn't ours to rely on.
(() => {
  "use strict"

  const PLAY_ICON = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M8 5v14l11-7z"></path></svg>'
  const HEREDOC_MARKER = "PYEOF"

  function buildCommand(extra, code) {
    const target = extra ? `ryjwt[${extra}]` : "ryjwt"
    const body = code.replace(/\n+$/, "")
    return `uv run --prerelease allow --with '${target}' python - <<'${HEREDOC_MARKER}'\n${body}\n${HEREDOC_MARKER}\n`
  }

  function copyToClipboard(text) {
    // The Clipboard API needs a secure context: GitHub Pages serves the site over HTTPS, and
    // `task docs` over http://localhost, which counts as one.
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text)
    }
    return Promise.reject(new Error("Clipboard API unavailable"))
  }

  function showCopied(button, label) {
    label.textContent = "Copied!"
    button.classList.add("md-uv-run--copied")
    window.setTimeout(() => {
      label.textContent = "Copy for uv"
      button.classList.remove("md-uv-run--copied")
    }, 1500)
  }

  function enhance(block) {
    if (block.dataset.uvEnhanced) {
      return
    }
    block.dataset.uvEnhanced = "1"

    const codeEl = block.querySelector("code")
    if (!codeEl) {
      return
    }

    const button = document.createElement("button")
    button.type = "button"
    button.className = "md-uv-run"
    button.title = "Copy a uv command that runs this example"
    button.innerHTML = PLAY_ICON

    const label = document.createElement("span")
    label.textContent = "Copy for uv"
    button.appendChild(label)

    button.addEventListener("click", () => {
      const command = buildCommand(block.dataset.uvExtra, codeEl.textContent || "")
      copyToClipboard(command)
        .then(() => showCopied(button, label))
        .catch((error) => console.error("ryjwt docs: couldn't copy the uv command", error))
    })

    block.parentNode.insertBefore(button, block)
  }

  function scan(root) {
    root.querySelectorAll("[data-uv-extra]").forEach(enhance)
  }

  function start() {
    scan(document.body)

    // `navigation.instant` swaps the page in without a full reload, so tagged blocks can appear
    // without DOMContentLoaded firing again. It replaces the whole content container, not just
    // what's inside it, so this watches the body, which stays.
    new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        mutation.addedNodes.forEach((node) => {
          if (node.nodeType !== Node.ELEMENT_NODE) {
            return
          }
          if (node.matches("[data-uv-extra]")) {
            enhance(node)
          }
          scan(node)
        })
      }
    }).observe(document.body, { childList: true, subtree: true })
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start)
  } else {
    start()
  }
})()
