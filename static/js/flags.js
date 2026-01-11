(function () {
  function fallbackHtml() {
    return '<span class="text-xl">&#127757;</span>';
  }

  function flagHtml(countryCode) {
    try {
      var cc = (countryCode || '').toString().trim().toLowerCase();
      if (!cc || cc.length !== 2 || !/^[a-z]{2}$/.test(cc)) {
        return fallbackHtml();
      }
      return (
        '<img ' +
        'src="https://flagcdn.com/24x18/' + cc + '.png" ' +
        'srcset="https://flagcdn.com/48x36/' + cc + '.png 2x" ' +
        'width="24" height="18" ' +
        'class="inline-block rounded-sm align-middle" ' +
        'alt="' + cc.toUpperCase() + ' flag" ' +
        'loading="lazy" ' +
        'referrerpolicy="no-referrer" ' +
        'onerror="this.outerHTML=\\\'&#127757;\\\'"' +
        ' />'
      );
    } catch (err) {
      return fallbackHtml();
    }
  }

  function renderFlags(root) {
    var scope = root || document;
    var nodes = scope.querySelectorAll('.flag-slot');
    nodes.forEach(function (node) {
      var cc = node.getAttribute('data-cc') || '';
      node.innerHTML = flagHtml(cc);
    });
  }

  window.flagHtml = flagHtml;
  window.renderFlags = renderFlags;
})();
