// ============================================================
// Helpers
// ============================================================
  const $ = id => document.getElementById(id);
  const SVG_NS = 'http://www.w3.org/2000/svg';

  const COLORS = {
    blue: '#4F7CAC', violet: '#6B5BA6', teal: '#3F7A72', gold: '#A8844A',
    navy: '#1F3A4D', err: '#A5484D', track: '#E6E0D6', tcp: '#2F5D8A',
    udp: '#6B5BA6', other: '#A8844A', nonip: '#9AA3AD'
  };

  const LABEL_TEXT = {
    normal: 'Normal-like traffic',
    vpn: 'VPN-like traffic',
    inconclusive: 'Inconclusive traffic'
  };

  const LABEL_COLOR = {
    normal: COLORS.teal,
    vpn: COLORS.gold,
    inconclusive: '#9AA3AD'
  };

  const FEATURES = [
    { key: 'entropy', name: 'Payload Entropy', color: COLORS.blue },
    { key: 'vpn_port', name: 'VPN Port Match', color: COLORS.violet },
    { key: 'packet_size', name: 'Packet Size', color: COLORS.teal },
    { key: 'timing_regularity', name: 'Timing Regularity', color: COLORS.gold }
  ];

  const DEFAULT_HINT = 'Generate some traffic during the capture, for example by opening a website. Payloads are never decrypted or stored.';

  let progressTimer = null;
  let captureRunning = false;
  let lastSample = [];
  let showAllSample = false;

  function fmt(value, digits = 2, suffix = '') {
    if (value === null || value === undefined || Number.isNaN(Number(value))) return '—';
    return Number(value).toFixed(digits) + suffix;
  }

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function svgEl(tag, attributes = {}) {
    const node = document.createElementNS(SVG_NS, tag);
    Object.keys(attributes).forEach(key => node.setAttribute(key, attributes[key]));
    return node;
  }

  function clamp(value, low, high) {
    return Math.max(low, Math.min(high, value));
  }

  function average(values) {
    const numbers = values.filter(v => v !== null && v !== undefined);
    if (numbers.length === 0) return null;
    return numbers.reduce((sum, v) => sum + v, 0) / numbers.length;
  }

  function cumulative(values) {
    let total = 0;
    return values.map(v => (total += v));
  }

  function statusClassFor(classification) {
    if (classification === 'vpn_like') return 'vpn';
    if (classification === 'normal_like') return 'normal';
    return 'inconclusive';
  }

  function setBackend(ok) {
    $('backendDot').className = 'dot ' + (ok ? 'ok' : 'bad');
    $('backendText').textContent = ok ? 'Backend Connected' : 'Backend Offline';
  }

  function showError(message) {
    const box = $('errorBox');
    box.textContent = message;
    box.style.display = 'block';
  }

  function hideError() {
    $('errorBox').style.display = 'none';
  }

  // ============================================================
  // Pages
  // ============================================================
  function showPage(name) {
    document.querySelectorAll('.page').forEach(page => {
      page.classList.toggle('hidden', page.id !== 'page-' + name);
    });

    document.querySelectorAll('.nav-item').forEach(button => {
      button.classList.toggle('active', button.dataset.page === name);
    });

    if (name === 'experiments') loadExperiments();
  }

  // ============================================================
  // Adapters
  // ============================================================
  async function loadInterfaces() {
    const select = $('ifaceSelect');
    select.innerHTML = '<option value="">Loading adapters…</option>';

    try {
      const response = await fetch('/interfaces');
      const data = await response.json().catch(() => ({}));

      setBackend(true);

      if (!response.ok || !data.interfaces || data.interfaces.length === 0) {
        select.innerHTML = '<option value="">No adapters found</option>';
        showError(data.error || 'No network adapters were found. Check that Npcap is installed.');
        return;
      }

      select.innerHTML = '';

      data.interfaces.forEach(item => {
        const option = document.createElement('option');
        option.value = item.name;
        option.textContent = item.description || item.name;
        select.appendChild(option);
      });

      const wifi = [...select.options].find(o =>
        /Wi-Fi/i.test(o.textContent) && !/Direct|Virtual/i.test(o.textContent)
      );

      if (wifi) select.value = wifi.value;

      hideError();

    } catch (err) {
      select.innerHTML = '<option value="">Could not reach backend</option>';
      setBackend(false);
      showError('Could not reach the backend. Make sure app.py is running.');
    }
  }

  // ============================================================
  // Capture
  // ============================================================
  async function startCapture() {
    if (captureRunning) return;

    hideError();

    const iface = $('ifaceSelect').value;
    const duration = parseInt($('durationInput').value, 10);

    if (!iface) {
      return showError('Select a network adapter first.');
    }

    if (Number.isNaN(duration) || duration < 3 || duration > 60) {
      return showError('Duration must be a whole number between 3 and 60 seconds.');
    }

    const ifaceName = $('ifaceSelect').selectedOptions[0].textContent;

    captureRunning = true;
    $('captureBtn').disabled = true;
    $('saveMsg').textContent = '';

    clearResults();
    renderPending();
    startProgress(duration, ifaceName);

    try {
      const startResponse = await fetch('/capture/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ interface: iface, duration })
      });

      const startData = await startResponse.json().catch(() => ({}));

      setBackend(true);

      if (!startResponse.ok) {
        throw new Error(startData.error || 'Could not start packet capture.');
      }

      while (true) {
        await new Promise(resolve => setTimeout(resolve, 400));

        const statusResponse = await fetch('/capture/status', {
          cache: 'no-store'
        });

        const status = await statusResponse.json().catch(() => ({}));

        if (!statusResponse.ok) {
          throw new Error(status.error || 'Could not read capture status.');
        }

        if (Array.isArray(status.timeline)) {
          renderTrafficChart(status.timeline);
          renderBytesChart(status.timeline);
          renderSparks(status.timeline);
        }

        $('hintText').textContent =
          status.status === 'analyzing'
            ? 'Capture finished. Analysing packet metadata and Tor exit-node matches…'
            : status.status === 'saving'
              ? 'Analysis complete. Automatically saving the classified result…'
              : `Capturing on ${ifaceName}… ${fmt(status.elapsed || 0, 1)} of ${duration} s. Keep browsing to generate traffic.`;

        // Automatically classified and saved by backend
        if (status.status === 'done' && status.result) {
          $('progressFill').style.width = '100%';

          renderFinal(status.result);

          if (status.auto_save_error) {
            $('saveMsg').className = 'msg err';
            $('saveMsg').textContent = status.auto_save_error;
          } else {
            $('saveMsg').className = 'msg ok';
            $('saveMsg').textContent =
              `Automatically classified and saved: ${status.result.label}.`;
          }

          break;
        }

        if (status.status === 'error') {
          throw new Error(status.error || 'Packet capture failed.');
        }
      }

    } catch (err) {
      setBackend(false);

      showError(
        err.message ||
        'Could not reach the backend. Make sure app.py is running as Administrator.'
      );

      resetVerdict('Capture failed', 'See the error message above.');

    } finally {
      stopProgress();
      captureRunning = false;
      $('captureBtn').disabled = false;
    }
  }

  function startProgress(duration, ifaceName) {
    const startedAt = performance.now();

    $('progressFill').style.width = '0%';

    const tick = () => {
      const elapsed = (performance.now() - startedAt) / 1000;
      const pct = clamp(elapsed / duration * 100, 0, 98);

      $('progressFill').style.width = pct + '%';

      $('hintText').textContent = elapsed < duration
        ? `Capturing on ${ifaceName}… ${fmt(elapsed, 0)} of ${duration} s. Keep browsing to generate traffic.`
        : 'Analysing captured packets…';
    };

    tick();
    progressTimer = setInterval(tick, 250);
  }

  function stopProgress() {
    clearInterval(progressTimer);
    progressTimer = null;
    $('hintText').textContent = DEFAULT_HINT;
  }

  // ============================================================
  // Sparklines
  // ============================================================
  function sparkline(box, values, color) {
    box.innerHTML = '';

    const W = 300, H = 44;

    const svg = svgEl('svg', {
      viewBox: `0 0 ${W} ${H}`,
      preserveAspectRatio: 'none'
    });

    if (values.length >= 2) {
      const max = Math.max(1, ...values);
      const step = W / (values.length - 1);

      const points = values.map((v, i) =>
        `${(i * step).toFixed(1)},${(H - 4 - (v / max) * (H - 10)).toFixed(1)}`
      );

      const line = points.join(' ');

      svg.appendChild(svgEl('polygon', {
        points: `0,${H} ${line} ${W},${H}`,
        fill: color,
        'fill-opacity': 0.14
      }));

      svg.appendChild(svgEl('polyline', {
        points: line,
        fill: 'none',
        stroke: color,
        'stroke-width': 2,
        'vector-effect': 'non-scaling-stroke'
      }));
    }

    box.appendChild(svg);
  }

  function renderSparks(timeline) {
    const packets = timeline.map(b => b.packets);

    sparkline($('spPackets'), packets, COLORS.blue);
    sparkline($('spAvg'), timeline.map(b => (b.packets ? b.bytes / b.packets : 0)), COLORS.violet);
    sparkline($('spSpan'), cumulative(packets), COLORS.teal);
    sparkline($('spIntervals'), packets, COLORS.gold);
  }

  function clearSparks() {
    ['spPackets', 'spAvg', 'spSpan', 'spIntervals'].forEach(id => {
      $(id).innerHTML = '';
    });
  }

  // ============================================================
  // Traffic chart
  // ============================================================
  function renderTrafficChart(timeline) {
    const box = $('liveChart');
    box.innerHTML = '';

    if (!Array.isArray(timeline) || timeline.length === 0) {
      box.appendChild(el(
        'p',
        'muted',
        'The backend did not return per-second data, so no chart can be drawn.'
      ));

      $('liveNote').textContent = '';
      return;
    }

    $('liveNote').textContent = `${timeline.length} s of traffic`;

    const W = 900, H = 240, L = 44, R = 12, T = 14, B = 28;
    const plotW = W - L - R;
    const plotH = H - T - B;

    const maxPackets = Math.max(10, ...timeline.map(b => b.packets));
    const slot = plotW / timeline.length;
    const barW = Math.max(3, slot * 0.6);

    const svg = svgEl('svg', {
      viewBox: `0 0 ${W} ${H}`,
      class: 'chart-svg'
    });

    [0, 0.5, 1].forEach(fraction => {
      const y = T + plotH * (1 - fraction);

      svg.appendChild(svgEl('line', {
        x1: L,
        x2: W - R,
        y1: y,
        y2: y,
        class: 'grid-line'
      }));

      const label = svgEl('text', {
        x: L - 8,
        y: y + 4,
        'text-anchor': 'end',
        class: 'axis-text'
      });

      label.textContent = Math.round(maxPackets * fraction);
      svg.appendChild(label);
    });

    timeline.forEach((bucket, i) => {
      const h = plotH * (bucket.packets / maxPackets);
      const x = L + slot * i + (slot - barW) / 2;

      const bar = svgEl('rect', {
        x: x,
        y: T + plotH - h,
        width: barW,
        height: h,
        rx: 2,
        fill: COLORS.blue
      });

      const title = svgEl('title');
      title.textContent =
        `Second ${i + 1}: ${bucket.packets} packets, ${bucket.bytes} bytes`;

      bar.appendChild(title);
      svg.appendChild(bar);
    });

    const labelStep = Math.max(1, Math.ceil(timeline.length / 8));

    for (let s = 0; s < timeline.length; s += labelStep) {
      const label = svgEl('text', {
        x: L + slot * s + slot / 2,
        y: H - 8,
        'text-anchor': 'middle',
        class: 'axis-text'
      });

      label.textContent = (s + 1) + ' s';
      svg.appendChild(label);
    }

    box.appendChild(svg);
  }

  function renderBytesChart(timeline) {
    const box = $('bytesChart');
    if (!box) return;

    box.innerHTML = '';

    if (!Array.isArray(timeline) || timeline.length === 0) {
      box.appendChild(el(
        'p',
        'muted',
        'No packet-byte measurements were returned for this capture.'
      ));

      $('bytesNote').textContent = '';
      return;
    }

    $('bytesNote').textContent = `${timeline.length} one-second buckets`;

    const W = 900, H = 210, L = 52, R = 12, T = 12, B = 28;
    const plotW = W - L - R;
    const plotH = H - T - B;

    const maxBytes = Math.max(1, ...timeline.map(b => Number(b.bytes) || 0));
    const slot = plotW / timeline.length;
    const barW = Math.max(3, slot * 0.6);

    const svg = svgEl('svg', {
      viewBox: `0 0 ${W} ${H}`,
      class: 'chart-svg'
    });

    [0, 0.5, 1].forEach(f => {
      const y = T + plotH * (1 - f);

      svg.appendChild(svgEl('line', {
        x1: L,
        x2: W - R,
        y1: y,
        y2: y,
        class: 'grid-line'
      }));

      const label = svgEl('text', {
        x: L - 8,
        y: y + 4,
        'text-anchor': 'end',
        class: 'axis-text'
      });

      label.textContent = Math.round(maxBytes * f).toLocaleString();
      svg.appendChild(label);
    });

    timeline.forEach((b, i) => {
      const value = Number(b.bytes) || 0;
      const h = plotH * value / maxBytes;

      const rect = svgEl('rect', {
        x: L + slot * i + (slot - barW) / 2,
        y: T + plotH - h,
        width: barW,
        height: h,
        rx: 2,
        fill: COLORS.teal
      });

      const title = svgEl('title');
      title.textContent = `Second ${i + 1}: ${value.toLocaleString()} bytes`;

      rect.appendChild(title);
      svg.appendChild(rect);
    });

    const step = Math.max(1, Math.ceil(timeline.length / 8));

    for (let i = 0; i < timeline.length; i += step) {
      const label = svgEl('text', {
        x: L + slot * i + slot / 2,
        y: H - 8,
        'text-anchor': 'middle',
        class: 'axis-text'
      });

      label.textContent = `${i + 1} s`;
      svg.appendChild(label);
    }

    box.appendChild(svg);
  }

  function renderIntervalHistogram(buckets) {
    const box = $('intervalChart');
    if (!box) return;

    box.innerHTML = '';

    if (!Array.isArray(buckets) || !buckets.length) {
      box.appendChild(el(
        'p',
        'muted',
        'Not enough packet timestamps to calculate inter-arrival intervals.'
      ));
      return;
    }

    const W = 520, H = 210, L = 42, R = 10, T = 12, B = 38;
    const plotW = W - L - R;
    const plotH = H - T - B;

    const maxCount = Math.max(1, ...buckets.map(b => b.count));

    const svg = svgEl('svg', {
      viewBox: `0 0 ${W} ${H}`,
      class: 'chart-svg'
    });

    [0, 0.5, 1].forEach(f => {
      const y = T + plotH * (1 - f);

      svg.appendChild(svgEl('line', {
        x1: L,
        x2: W - R,
        y1: y,
        y2: y,
        class: 'grid-line'
      }));

      const t = svgEl('text', {
        x: L - 7,
        y: y + 4,
        'text-anchor': 'end',
        class: 'axis-text'
      });

      t.textContent = Math.round(maxCount * f);
      svg.appendChild(t);
    });

    const slot = plotW / buckets.length;
    const bw = slot * 0.62;

    buckets.forEach((b, i) => {
      const h = plotH * b.count / maxCount;
      const x = L + i * slot + (slot - bw) / 2;

      const rect = svgEl('rect', {
        x,
        y: T + plotH - h,
        width: bw,
        height: h,
        rx: 2,
        fill: COLORS.violet
      });

      const title = svgEl('title');
      title.textContent = `${b.label}: ${b.count} intervals`;

      rect.appendChild(title);
      svg.appendChild(rect);

      const label = svgEl('text', {
        x: x + bw / 2,
        y: H - 10,
        'text-anchor': 'middle',
        class: 'axis-text'
      });

      label.textContent = b.label;
      svg.appendChild(label);
    });

    box.appendChild(svg);
  }

  // ============================================================
  // Tor information
  // ============================================================
  function renderTor(tor) {
    if (!tor) return;

    $('torChecked').textContent =
      Number(tor.ip_packets || 0).toLocaleString();

    $('torMatches').textContent =
      Number(tor.matched_packets || 0).toLocaleString();

    $('torListSize').textContent =
      Number(tor.list_size || 0).toLocaleString();

    const statusNames = {
      downloaded: 'List downloaded',
      cache: 'Using fresh cache',
      cache_stale: 'Using stale/manual cache',
      unavailable: 'List unavailable'
    };

    $('torStatus').textContent =
      statusNames[tor.list_status] || 'List status unknown';

    const age = tor.list_age_hours == null
      ? 'unknown age'
      : `${tor.list_age_hours} hours old`;

    $('torExplanation').textContent =
      tor.list_status === 'unavailable'
        ? 'Tor list is unavailable. Check internet access or place a valid public exit-node list in results/tor_exit_list.txt. No Tor conclusion can be made.'
        : `${tor.matched_packets || 0} of ${tor.ip_packets || 0} IPv4 packets touched a listed Tor exit-node address. List: ${age}. A match is an indicator, not proof of Tor Browser use; zero matches do not rule out Tor because clients usually connect to guard/relay nodes.`;
  }

  // ============================================================
  // Results
  // ============================================================
  function renderFinal(r) {
    $('stPackets').textContent =
      r.traffic.total_packets.toLocaleString();

    $('stAvg').textContent =
      fmt(r.size.mean_bytes, 1, ' B');

    $('stSpan').textContent =
      fmt(r.traffic.capture_span_sec, 2, ' s');

    $('stIntervals').textContent =
      r.timing.interval_count.toLocaleString();

    if (Array.isArray(r.timeline) && r.timeline.length) {
      renderSparks(r.timeline);
    }

    renderTrafficChart(r.timeline);
    renderBytesChart(r.timeline);

    renderIntervalHistogram(
      r.timing && r.timing.interval_histogram
    );

    renderTor(r.tor);
    renderVerdict(r);
    renderFeatureBars(r.score_breakdown);
    renderDonut(r.traffic);
    renderHistogram(r.size_histogram);

    lastSample = r.packet_sample || [];
    renderSample();
  }

  function renderVerdict(r) {
    const pill = $('verdictPill');

    pill.textContent = r.label;
    pill.className = 'verdict-pill ' + statusClassFor(r.classification);

    $('reasonText').textContent = r.reason;
    $('scoreValue').textContent = fmt(r.heuristic_score, 1);

    $('scoreFill').style.width =
      clamp(r.heuristic_score, 0, 100) + '%';
  }

  function renderPending() {
    resetVerdict(
      'Capture in progress',
      'The result appears when the capture finishes.'
    );
  }

  function resetVerdict(title, reason) {
    const pill = $('verdictPill');

    pill.textContent = title;
    pill.className = 'verdict-pill';

    $('reasonText').textContent = reason;
    $('scoreValue').textContent = '--';
    $('scoreFill').style.width = '0%';
  }

  function clearResults() {
    resetVerdict(
      'No result yet',
      'Run a capture to see the result.'
    );

    $('stPackets').textContent = '--';
    $('stAvg').textContent = '--';
    $('stSpan').textContent = '--';
    $('stIntervals').textContent = '--';

    clearSparks();

    $('liveNote').textContent = '';

    $('liveChart').innerHTML =
      '<p class="muted">The chart appears from live packet counters.</p>';

    $('bytesChart').innerHTML =
      '<p class="muted">The chart appears from live packet lengths.</p>';

    $('bytesNote').textContent = '';

    $('intervalChart').innerHTML =
      '<p class="muted">Shows the distribution of gaps between captured packet timestamps.</p>';

    $('torChecked').textContent = '--';
    $('torMatches').textContent = '--';
    $('torListSize').textContent = '--';

    $('torStatus').textContent = 'Waiting for capture';

    $('torExplanation').textContent =
      'Run a capture to compare observed IPv4 packet endpoints with the Tor exit-node list. A zero match does not rule out Tor usage.';

    renderFeatureBars(null);

    $('donutBox').innerHTML = '';
    $('donutLegend').innerHTML = '';
    $('histBox').innerHTML = '';

    lastSample = [];
    renderSample();
  }

  function renderFeatureBars(breakdown) {
    const box = $('featureBars');
    box.innerHTML = '';

    FEATURES.forEach(feature => {
      const item = breakdown ? breakdown[feature.key] : null;
      const pct = item ? item.value * 100 : 0;

      const row = el('div', 'fbar');

      row.appendChild(el('span', '', feature.name));

      const track = el('div', 'track');
      const fill = el('div', 'fill');

      fill.style.width = pct + '%';
      fill.style.background = feature.color;

      track.appendChild(fill);
      row.appendChild(track);

      row.appendChild(
        el('span', 'val', item ? fmt(pct, 0, '%') : '--')
      );

      box.appendChild(row);
    });
  }

  function renderDonut(traffic) {
    const box = $('donutBox');
    const legend = $('donutLegend');

    box.innerHTML = '';
    legend.innerHTML = '';

    const total = traffic.total_packets || 0;

    const parts = [
      ['TCP', traffic.tcp_packets, COLORS.tcp],
      ['UDP', traffic.udp_packets, COLORS.udp],
      ['Other IP', traffic.other_ipv4_packets, COLORS.other],
      ['Non-IPv4', traffic.non_ipv4_packets, COLORS.nonip]
    ];

    const R = 56;
    const C = 2 * Math.PI * R;

    const svg = svgEl('svg', {
      viewBox: '0 0 150 150',
      class: 'donut'
    });

    svg.appendChild(svgEl('circle', {
      cx: 75,
      cy: 75,
      r: R,
      fill: 'none',
      stroke: COLORS.track,
      'stroke-width': 20
    }));

    let offset = 0;

    parts.forEach(([name, count, color]) => {
      if (!total || !count) return;

      const length = C * count / total;

      svg.appendChild(svgEl('circle', {
        cx: 75,
        cy: 75,
        r: R,
        fill: 'none',
        stroke: color,
        'stroke-width': 20,
        'stroke-dasharray': `${length} ${C - length}`,
        'stroke-dashoffset': -offset,
        transform: 'rotate(-90 75 75)'
      }));

      offset += length;
    });

    const centre = svgEl('text', {
      x: 75,
      y: 73,
      'text-anchor': 'middle',
      class: 'donut-total'
    });

    centre.textContent = total.toLocaleString();
    svg.appendChild(centre);

    const caption = svgEl('text', {
      x: 75,
      y: 91,
      'text-anchor': 'middle',
      class: 'donut-sub'
    });

    caption.textContent = 'Packets';
    svg.appendChild(caption);

    box.appendChild(svg);

    parts.forEach(([name, count, color]) => {
      const row = el('div', 'legend-row');

      const swatch = el('span', 'swatch');
      swatch.style.background = color;

      row.appendChild(swatch);
      row.appendChild(el('span', '', name));
      row.appendChild(el('span', 'n', count));

      row.appendChild(
        el('span', 'n', fmt(total ? count / total * 100 : 0, 0, '%'))
      );

      legend.appendChild(row);
    });
  }

    function renderHistogram(buckets) {
    const box = $('histBox');
    box.innerHTML = '';

    if (!buckets || buckets.length === 0) {
      box.appendChild(el(
        'p',
        'muted',
        'Shown after a capture finishes. (The backend did not return size-histogram data.)'
      ));
      return;
    }

    const W = 360, H = 210, L = 34, R = 8, T = 10, B = 28;
    const plotW = W - L - R;
    const plotH = H - T - B;

    const maxCount = Math.max(1, ...buckets.map(b => b.count));

    const svg = svgEl('svg', {
      viewBox: `0 0 ${W} ${H}`,
      class: 'chart-svg'
    });

    [0, 0.5, 1].forEach(fraction => {
      const y = T + plotH * (1 - fraction);

      svg.appendChild(svgEl('line', {
        x1: L,
        x2: W - R,
        y1: y,
        y2: y,
        class: 'grid-line'
      }));

      const label = svgEl('text', {
        x: L - 6,
        y: y + 4,
        'text-anchor': 'end',
        class: 'axis-text'
      });

      label.textContent = Math.round(maxCount * fraction);
      svg.appendChild(label);
    });

    const slot = plotW / buckets.length;
    const barW = slot * 0.7;
    const labelStep = Math.max(1, Math.ceil(buckets.length / 5));

    buckets.forEach((bucket, i) => {
      const h = plotH * (bucket.count / maxCount);
      const x = L + slot * i + (slot - barW) / 2;

      const bar = svgEl('rect', {
        x: x,
        y: T + plotH - h,
        width: barW,
        height: h,
        rx: 2,
        fill: COLORS.blue
      });

      const title = svgEl('title');
      title.textContent = `${bucket.label} bytes: ${bucket.count} packets`;

      bar.appendChild(title);
      svg.appendChild(bar);

      // Only show a few evenly spaced labels to prevent overlap.
      if (i % labelStep === 0 || i === buckets.length - 1) {
        const label = svgEl('text', {
          x: x + barW / 2,
          y: H - 8,
          'text-anchor': 'middle',
          class: 'axis-text'
        });

        label.textContent = bucket.label;
        svg.appendChild(label);
      }
    });

    box.appendChild(svg);
    box.appendChild(el('p', 'cap', 'Packet size (bytes)'));
  }

  // ============================================================
  // Packet sample
  // ============================================================
  function renderSample() {
    const body = $('sampleBody');
    body.innerHTML = '';

    const rows = showAllSample
      ? lastSample
      : lastSample.slice(0, 10);

    $('sampleToggle').textContent =
      showAllSample ? 'Show first 10' : 'View All';

    $('sampleTitle').textContent =
      showAllSample
        ? 'Packet Summary (sample of up to 30)'
        : 'Packet Summary (first 10)';

    if (rows.length === 0) {
      const tr = document.createElement('tr');

      const td = el(
        'td',
        'muted',
        'Shown after a capture finishes.'
      );

      td.colSpan = 6;
      td.style.textAlign = 'left';

      tr.appendChild(td);
      body.appendChild(tr);
      return;
    }

    rows.forEach(row => {
      const tr = document.createElement('tr');

      tr.appendChild(el('td', 'left', row.number));
      tr.appendChild(el('td', '', fmt(row.time_rel_sec, 4)));
      tr.appendChild(el('td', '', row.protocol));

      tr.appendChild(el(
        'td',
        '',
        row.src_port === null ? '—' : row.src_port
      ));

      tr.appendChild(el(
        'td',
        '',
        row.dst_port === null ? '—' : row.dst_port
      ));

      tr.appendChild(el('td', '', row.size_bytes));

      body.appendChild(tr);
    });
  }

  function toggleSample() {
    showAllSample = !showAllSample;
    renderSample();
  }

  // ============================================================
  // Experiments page
  // ============================================================
  let experimentRows = [];

  async function loadExperiments() {
    setExpMessage('Loading…', '');

    try {
      const response = await fetch('/experiments');
      const data = await response.json();

      if (!response.ok) {
        setExpMessage(data.error || 'Could not load experiments.', 'err');
        return;
      }

      experimentRows = data.experiments || [];

      renderExperiments(experimentRows);
      setExpMessage('', '');

    } catch (err) {
      setExpMessage('Could not reach the backend.', 'err');
    }
  }

  function setExpMessage(text, kind) {
    const node = $('expMsg');

    node.textContent = text;
    node.className = 'msg' + (kind ? ' ' + kind : '');
  }

  function renderExperiments(rows) {
    $('expCount').textContent =
      `${rows.length} saved run${rows.length === 1 ? '' : 's'}`;

    renderComparison(rows);
    renderScoreChart(rows);
    renderExperimentTable(rows);
  }

  // ============================================================
  // Comparison
  // ============================================================
  function renderComparison(rows) {
    const body = $('compareBody');
    body.innerHTML = '';

    ['normal', 'vpn', 'inconclusive'].forEach(code => {
      const group = rows.filter(r => r.label_code === code);

      const tr = document.createElement('tr');

      tr.appendChild(
        el('td', 'left', LABEL_TEXT[code])
      );

      if (group.length === 0) {
        const td = el('td', 'muted', 'No saved runs yet');

        td.colSpan = 7;
        td.style.textAlign = 'left';

        tr.appendChild(td);
        body.appendChild(tr);
        return;
      }

      tr.appendChild(el('td', '', group.length));

      tr.appendChild(el(
        'td',
        '',
        fmt(average(group.map(r => r.heuristic_score)), 1)
      ));

      tr.appendChild(el(
        'td',
        '',
        fmt(average(group.map(r => r.mean_normalized_entropy)), 3)
      ));

      tr.appendChild(el(
        'td',
        '',
        fmt(average(group.map(r => r.vpn_port_match_ratio)), 3)
      ));

      tr.appendChild(el(
        'td',
        '',
        fmt(average(group.map(r => r.mean_frame_bytes)), 1)
      ));

      tr.appendChild(el(
        'td',
        '',
        fmt(average(group.map(r => r.mean_gap_ms)), 3)
      ));

      tr.appendChild(el(
        'td',
        '',
        fmt(average(group.map(r => r.total_packets)), 0)
      ));

      body.appendChild(tr);
    });
  }

  // ============================================================
  // Score chart
  // ============================================================
  function renderScoreChart(rows) {
    const box = $('scoreChart');
    box.innerHTML = '';

    if (rows.length === 0) {
      box.appendChild(el(
        'p',
        'muted',
        'No saved runs yet. Start a capture to automatically classify and save its result.'
      ));
      return;
    }

    const W = 900, H = 260, L = 40, R = 12, T = 16, B = 30;
    const plotW = W - L - R;
    const plotH = H - T - B;

    const svg = svgEl('svg', {
      viewBox: `0 0 ${W} ${H}`,
      class: 'chart-svg'
    });

    [0, 50, 100].forEach(value => {
      const y = T + plotH * (1 - value / 100);

      svg.appendChild(svgEl('line', {
        x1: L,
        x2: W - R,
        y1: y,
        y2: y,
        class: 'grid-line'
      }));

      const label = svgEl('text', {
        x: L - 8,
        y: y + 4,
        'text-anchor': 'end',
        class: 'axis-text'
      });

      label.textContent = String(value);
      svg.appendChild(label);
    });

    [40, 60].forEach(value => {
      const y = T + plotH * (1 - value / 100);

      svg.appendChild(svgEl('line', {
        x1: L,
        x2: W - R,
        y1: y,
        y2: y,
        stroke: COLORS.gold,
        'stroke-width': 1,
        'stroke-dasharray': '4 4'
      }));
    });

    const slot = plotW / rows.length;
    const barW = Math.min(44, slot * 0.6);

    rows.forEach((row, index) => {
      const score = clamp(Number(row.heuristic_score) || 0, 0, 100);
      const h = plotH * (score / 100);
      const x = L + slot * index + (slot - barW) / 2;

      const bar = svgEl('rect', {
        x: x,
        y: T + plotH - h,
        width: barW,
        height: Math.max(h, 1),
        fill: LABEL_COLOR[row.label_code] || COLORS.navy,
        rx: 2
      });

      const title = svgEl('title');

      title.textContent =
        `Run ${index + 1}: ${LABEL_TEXT[row.label_code] || row.label_code}, score ${fmt(row.heuristic_score, 1)}`;

      bar.appendChild(title);
      svg.appendChild(bar);

      const tick = svgEl('text', {
        x: x + barW / 2,
        y: H - 10,
        'text-anchor': 'middle',
        class: 'axis-text'
      });

      tick.textContent = String(index + 1);
      svg.appendChild(tick);
    });

    box.appendChild(svg);
  }

  // ============================================================
  // Classification text
  // ============================================================
  function classificationText(code) {
    if (code === 'vpn_like') return 'VPN-like';
    if (code === 'normal_like') return 'Normal-like';
    return 'Inconclusive';
  }

  // ============================================================
  // Experiment table
  // ============================================================
  function renderExperimentTable(rows) {
    const body = $('expBody');
    body.innerHTML = '';

    if (rows.length === 0) {
      const tr = document.createElement('tr');

      const td = el('td', 'muted', 'No saved runs yet.');

      td.colSpan = 8;
      td.style.textAlign = 'left';

      tr.appendChild(td);
      body.appendChild(tr);
      return;
    }

    rows.forEach((row, index) => {
      const tr = document.createElement('tr');

      tr.appendChild(el('td', 'left', index + 1));

      tr.appendChild(el(
        'td',
        'left',
        LABEL_TEXT[row.label_code] || row.label
      ));

      tr.appendChild(el('td', 'left', row.captured_at));
      tr.appendChild(el('td', 'left', row.interface));
      tr.appendChild(el('td', '', row.total_packets));

      tr.appendChild(el(
        'td',
        '',
        fmt(row.heuristic_score, 1)
      ));

      tr.appendChild(el(
        'td',
        'left',
        classificationText(row.classification)
      ));

      const actionCell = el('td', '');

      const deleteBtn = el('button', 'danger-btn', 'Delete');

      deleteBtn.onclick = () => deleteExperiment(row.id);

      actionCell.appendChild(deleteBtn);
      tr.appendChild(actionCell);

      body.appendChild(tr);
    });
  }

  // ============================================================
  // Delete experiment
  // ============================================================
  async function deleteExperiment(id) {
    if (!confirm('Delete this saved run? This cannot be undone.')) {
      return;
    }

    try {
      const response = await fetch(
        '/experiments/' + encodeURIComponent(id),
        { method: 'DELETE' }
      );

      const data = await response.json();

      if (!response.ok) {
        setExpMessage(
          data.error || 'Could not delete the run.',
          'err'
        );
        return;
      }

      setExpMessage('Run deleted.', 'ok');
      loadExperiments();

    } catch (err) {
      setExpMessage('Could not reach the backend.', 'err');
    }
  }

  // ============================================================
  // Start
  // ============================================================
  window.addEventListener('load', () => {
    clearResults();
    loadInterfaces();
  });