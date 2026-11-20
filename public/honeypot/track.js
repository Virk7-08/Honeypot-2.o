(function () {
  function simpleHash(str) {
    let h = 0;
    for (let i = 0; i < str.length; i++) {
      h = (Math.imul(31, h) + str.charCodeAt(i)) | 0;
    }
    return (h >>> 0).toString(16);
  }

  function collectFingerprint() {
    const data = {
      screen: screen.width + 'x' + screen.height + '@' + (window.devicePixelRatio || 1),
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      language: navigator.language,
      languages: (navigator.languages || []).join(','),
      platform: navigator.platform,
      hardwareConcurrency: navigator.hardwareConcurrency,
      cookiesEnabled: navigator.cookieEnabled,
      touch: 'ontouchstart' in window
    };

    try {
      const canvas = document.createElement('canvas');
      const ctx = canvas.getContext('2d');
      ctx.textBaseline = 'top';
      ctx.font = '14px Arial';
      ctx.fillText('hp2.0-fingerprint', 2, 2);
      data.canvas = canvas.toDataURL();
    } catch (e) {
      data.canvas = null;
    }

    return { raw: data, hash: simpleHash(JSON.stringify(data)) };
  }

  function send(payload) {
    fetch('/api/track', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      keepalive: true
    }).catch(function () {});
  }

  const fp = collectFingerprint();
  const notice = document.getElementById('locNotice');

  function report(geoPayload) {
    send({ fingerprintHash: fp.hash, fingerprint: fp.raw, geo: geoPayload });
  }

  if ('geolocation' in navigator) {
    navigator.geolocation.getCurrentPosition(
      function (pos) {
        if (notice) notice.textContent = 'Location confirmed. Redirecting…';
        report({
          permission: 'granted',
          lat: pos.coords.latitude,
          lon: pos.coords.longitude,
          accuracy: pos.coords.accuracy
        });
      },
      function () {
        if (notice) notice.textContent = 'Continuing without location.';
        report({ permission: 'denied', lat: null, lon: null, accuracy: null });
      },
      { enableHighAccuracy: true, timeout: 8000 }
    );
  } else {
    report({ permission: 'unsupported', lat: null, lon: null, accuracy: null });
  }
})();
