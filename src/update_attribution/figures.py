#!/usr/bin/env python3
"""Figures for the SAC 2027 version of the paper.

Reads the derived tables in data/derived/ (outputs of controlled_attribution.py,
retrospective_attribution.py, keyword_baseline.py and entropy_by_channel.py; no raw
captures needed) and writes vector PDFs to latex/suit_acm_sigconf/fig/:

  traffic_composition.pdf   share of flows / bytes that are update traffic, per device
  keyword_baseline.pdf      what a naive keyword filter matches, and what it misses
  update_timelines.pdf      update exchanges over time for four devices (full text width)
  entropy_by_channel.pdf    per-flow payload entropy, grouped by how the flow is protected
  offered_negotiated.pdf    offered cipher suites per client configuration vs negotiated
  leaf_lifetimes.pdf        validity of update-server leaf certificates
  channel_image.pdf         channel protection of the image vs protection of the image

Typesetting: figure text is set by pdflatex in the paper's own fonts (Linux Biolinum,
the sans-serif of the ACM template) through matplotlib's PGF backend, and every figure
is saved at exactly the width it is printed at (one column, or the full text width for
the timelines), without tight-bbox cropping. The font sizes below are therefore the
printed sizes: 8 pt labels and titles, 7.5 pt tick labels, 7 pt annotations, against
9 pt body text. Include the PDFs at \\linewidth (\\textwidth for the timelines).

Colors: a four-step good-to-bad scale (validated with the dataviz palette checks:
lightness band, chroma floor, CVD and normal-vision separation of adjacent classes)
for protection levels, categorical slots 1-2 for CA type, and emphasis (one hue plus
grays) for the traffic-composition figure. Every figure has a legend or direct
labels, and the underlying values are in the paper's tables.

Usage: python3 src/update_attribution/figures.py [--only NAME]
"""
import argparse
import collections
import csv
import random
import sys
from pathlib import Path

import matplotlib
matplotlib.use('pgf')
import matplotlib.pyplot as plt  # noqa: E402
import matplotlib.ticker  # noqa: E402
from matplotlib.patches import Patch  # noqa: E402
from matplotlib.lines import Line2D  # noqa: E402
from matplotlib.transforms import blended_transform_factory  # noqa: E402

from paths import DERIVED_CONTROLLED as CTRL, DERIVED_RETRO as RETRO, FIGURES as FIG  # noqa: E402

# ---- style -------------------------------------------------------------------------
INK, INK2, MUTED, GRID, BASE = '#0b0b0b', '#52514e', '#898781', '#e1e0d9', '#c3c2b7'
GOOD2BAD = ['#1c5cab', '#5598e7', '#eb6834', '#b52b2b']       # validated 4-step scale
BLUE, ORANGE = '#2a78d6', '#eb6834'                              # categorical slots 1-2
GRAY_WAN, GRAY_LAN = '#b8b7b0', '#dcdbd5'                        # de-emphasis grays
COL_W, TXT_W = 241.14 / 72, 506.295 / 72                         # ACM sigconf widths (in)
FS, FS_TICK, FS_NOTE = 8, 7.5, 7                                 # printed sizes (pt)

plt.rcParams.update({
    'pgf.texsystem': 'pdflatex', 'pgf.rcfonts': False,
    'pgf.preamble': r'\usepackage[T1]{fontenc}\usepackage[tt=false,type1=true]{libertine}'
                    r'\renewcommand{\familydefault}{\sfdefault}',
    'font.family': 'sans-serif', 'font.size': FS, 'axes.titlesize': FS, 'axes.labelsize': FS,
    'xtick.labelsize': FS_TICK, 'ytick.labelsize': FS_TICK, 'legend.fontsize': FS_TICK,
    'axes.edgecolor': BASE, 'axes.linewidth': 0.6, 'axes.labelcolor': INK2, 'axes.titlecolor': INK,
    'xtick.color': BASE, 'ytick.color': BASE, 'xtick.labelcolor': INK2, 'ytick.labelcolor': INK,
    'xtick.major.width': 0.6, 'ytick.major.width': 0, 'xtick.major.size': 2.5, 'xtick.major.pad': 1.5,
    'ytick.major.pad': 2, 'axes.labelpad': 2, 'axes.titlepad': 3,
    'axes.spines.top': False, 'axes.spines.right': False,
    'legend.frameon': False, 'legend.handlelength': 1.0, 'legend.handletextpad': 0.4,
    'legend.columnspacing': 1.1, 'legend.borderaxespad': 0.2,
    'figure.constrained_layout.use': True,
    'figure.constrained_layout.w_pad': 1 / 72, 'figure.constrained_layout.h_pad': 1 / 72,
    'savefig.bbox': None, 'savefig.pad_inches': 0,
})

DEVICE_ORDER = ['apple-tv', 'homepod', 'eufy-cam', 'xiaomi-cam', 'tapo-c100', 'tapo-c200',
                'reolink-cam', 'fire-tv', 'sony-tv', 'd-link-cam']


def tex(s):
    """Escape the characters that pdflatex would otherwise interpret (% is handled by
    the PGF backend)."""
    return s.replace('_', r'\_').replace('#', r'\#').replace('&', r'\&')


def fig_left_text(ax, y, text, **kw):
    """Text that starts at the left edge of the figure, at data height y of ax (or, with
    axes_y=True, at axes-fraction height y). Used for panel titles and group headers
    that would otherwise start after the tick labels and run off the right edge."""
    axes_y = kw.pop('axes_y', False)
    tr = blended_transform_factory(ax.figure.transFigure, ax.transAxes if axes_y else ax.transData)
    return ax.text(0.004, y, text, transform=tr, ha='left', **kw)


def rows(path):
    with open(path, newline='') as fh:
        return list(csv.DictReader(fh))


def vgrid(ax):
    ax.xaxis.grid(True, color=GRID, linewidth=0.5)
    ax.set_axisbelow(True)


def save(fig, name):
    FIG.mkdir(parents=True, exist_ok=True)
    fig.savefig(FIG / f'{name}.pdf')
    w, h = fig.get_size_inches()
    plt.close(fig)
    print(f'wrote {FIG / name}.pdf ({w:.2f} x {h:.2f} in)')


# ---- 1. traffic composition --------------------------------------------------------
def traffic_composition():
    flows = rows(CTRL / 'flows.csv')
    per = collections.defaultdict(lambda: collections.Counter())
    for f in flows:
        cat = 'update' if f['endpoint'] else ('lan' if f['lan'] == 'True' else 'wan')
        per[f['device']][('n', cat)] += 1
        per[f['device']][('b', cat)] += int(f['bytes_up']) + int(f['bytes_down'])
    fig, axes = plt.subplots(1, 2, figsize=(COL_W, 2.05), sharey=True)
    cats = [('update', BLUE, 'update traffic'), ('wan', GRAY_WAN, 'other Internet traffic'),
            ('lan', GRAY_LAN, 'local network')]
    y = list(range(len(DEVICE_ORDER)))[::-1]
    for ax, key, title in ((axes[0], 'n', 'Share of flows'), (axes[1], 'b', 'Share of bytes')):
        for yi, dev in zip(y, DEVICE_ORDER):
            tot = sum(per[dev][(key, c)] for c, _, _ in cats) or 1
            left = 0.0
            for c, col, _ in cats:
                w = per[dev][(key, c)] / tot
                if w > 0:
                    ax.barh(yi, max(w - 0.006, 0.001), left=left, height=0.66, color=col, linewidth=0)
                left += w
            share = per[dev][(key, 'update')] / tot
            txt = '0%' if share == 0 else ('<1%' if share < 0.01 else f'{100 * share:.0f}%')
            ax.text(1.03, yi, txt, va='center', ha='left', fontsize=FS_NOTE, color=INK2)
        ax.set_xlim(0, 1)
        ax.set_xticks([0, 0.5, 1])
        ax.set_xticklabels(['0', '50%', '100%'])
        ax.set_title(title, loc='left')
        ax.tick_params(axis='y', length=0)
    axes[0].set_yticks(y)
    axes[0].set_yticklabels(DEVICE_ORDER)
    axes[1].spines['left'].set_visible(False)
    handles = [Patch(color=col, label=lab) for _, col, lab in cats]
    fig.legend(handles=handles, loc='outside lower center', ncol=3)
    save(fig, 'traffic_composition')


# ---- 2. keyword baseline -----------------------------------------------------------
def keyword_baseline():
    sel = rows(RETRO / 'keyword_baseline.csv')
    confirmed = {r['capture'] for r in rows(RETRO / 'update_flows.csv')}
    n = len(sel)
    cats = collections.Counter()
    # protocol vocabulary: labels and fields that never name an update server
    vocab = {'tcp-window-update', 'sip', 'stun', 'ocsp', 'tls-field'}
    only_vocab = 0
    for r in sel:
        cs = [c for c in r['categories'].split(';') if c]
        for c in set(cs):
            cats['other dissector label' if c.startswith('other:') else c] += 1
        if cs and all(c in vocab or c.startswith('other:') for c in cs):
            only_vocab += 1
    selected = {r['capture'] for r in sel}
    hit = len(confirmed & selected)
    accidental = sum(1 for r in sel if r['capture'] in confirmed and
                     all(c in vocab or c.startswith('other:') for c in r['categories'].split(';') if c))
    labels = [('tcp-window-update', 'TCP window-update annotation'), ('stun', 'STUN SOFTWARE attribute'),
              ('sip', 'SIP UPDATE method'), ('ocsp', 'OCSP thisUpdate/nextUpdate'),
              ('other dissector label', 'other protocol fields'), ('app-content', 'HTTP, XML, or JSON content'),
              ('dns-name', 'DNS name'), ('certificate-name', 'certificate name'),
              ('tls-server-name', 'TLS server name')]
    fig, (ax, ax2) = plt.subplots(2, 1, figsize=(COL_W, 2.45), gridspec_kw={'height_ratios': [4.6, 1.55]})
    ys = list(range(len(labels)))[::-1]
    for yi, (k, lab) in zip(ys, labels):
        v = cats[k] / n
        col = GRAY_WAN if k in vocab or k == 'other dissector label' else BLUE
        ax.barh(yi, max(v, 0.002), height=0.66, color=col, linewidth=0)
        ax.text(v + 0.015, yi, f'{100 * v:.0f}%' if v >= 0.01 else '<1%', va='center', fontsize=FS_NOTE,
                color=INK2)
    ax.set_yticks(ys)
    ax.set_yticklabels([lab for _, lab in labels])
    ax.set_xlim(0, 1)
    ax.set_xticks([0, 0.25, 0.5, 0.75, 1])
    ax.set_xticklabels(['0', '25%', '50%', '75%', '100%'])
    vgrid(ax)
    fig_left_text(ax, 1.03, f'(a) Where the keywords occur ({n:,} selected captures)', axes_y=True,
                  va='bottom', fontsize=FS, color=INK)
    ax.tick_params(axis='y', length=0)
    # (b) precision, and how the 308 update captures were matched
    segs_b = [[(hit, BLUE), (n - hit, GRAY_LAN)], [(hit - accidental, BLUE), (accidental, GRAY_WAN)]]
    for yi, segs in zip([1, 0], segs_b):
        tot = sum(v for v, _ in segs)
        left = 0.0
        for v, col in segs:
            w = v / tot
            ax2.barh(yi, max(w - 0.006, 0.002), left=left, height=0.62, color=col, linewidth=0)
            left += w
    ax2.text(hit / n + 0.015, 1, f'{hit} ({100 * hit / n:.1f}%) with update traffic', va='center', ha='left',
             fontsize=FS_NOTE, color=INK)
    ax2.text(0.02, 0, f'{hit - accidental} via update names or content', va='center', ha='left',
             fontsize=FS_NOTE, color='white')
    ax2.text(1 - accidental / hit / 2, 0, f'{accidental}', va='center', ha='center', fontsize=FS_NOTE, color=INK)
    ax2.set_yticks([1, 0])
    ax2.set_yticklabels(['selected captures', 'with update traffic'])
    ax2.tick_params(axis='y', length=0)
    ax2.set_xlim(0, 1)
    ax2.set_xticks([0, 0.5, 1])
    ax2.set_xticklabels(['0', '50%', '100%'])
    fig_left_text(ax2, 1.06, '(b) How many selected captures contain update traffic', axes_y=True,
                  va='bottom', fontsize=FS, color=INK)
    save(fig, 'keyword_baseline')
    res = dict(selected=n, only_vocab=f'{100 * only_vocab / n:.0f}%', hit=hit, confirmed=len(confirmed),
               accidental=accidental, recall=f'{100 * hit / len(confirmed):.0f}%',
               precision=f'{100 * hit / n:.1f}%', **{k: f'{100 * cats[k] / n:.0f}%' for k, _ in labels})
    print('keyword baseline numbers:', res)
    return res


# ---- 3. update timelines -----------------------------------------------------------
SHORT = {'updates.cdn-apple.com': 'updates.cdn-apple.com (image)', 'mesu.apple.com': 'mesu.apple.com (catalog)',
         'gdmf.apple.com': 'gdmf.apple.com (metadata)', 'gdmf-ados.apple.com': 'gdmf-ados.apple.com (metadata)',
         'gs.apple.com': 'gs.apple.com (authorization)',
         'updates-http.cdn-apple.com': 'updates-http.cdn-apple.com (asset)',
         'download.tplinkcloud.com': 'download.tplinkcloud.com (image)',
         'n-device-api.tplinkcloud.com': 'TP-Link device API',
         'n-euw1-device-api.tplinkcloud.com': 'TP-Link device API',
         'n-euw1-devs-dcipc.tplinkcloud.com': 'TP-Link device API',
         'n-deventry-dcipc.tplinkcloud.com': 'TP-Link device API',
         'fk-res-abroad-cdn.home.mi.com': 'fk-res-abroad-cdn.home.mi.com (image)',
         'de.ots.io.mi.com': 'de.ots.io.mi.com (device channel)',
         'cdn-eu-public.eufylife.com': 'cdn-eu-public (image)', 'security-app-eu.eufylife.com': 'security-app-eu (API)',
         'LAN:192.168.0.11': 'desktop application (image)'}


def channel_color(f):
    if f['lan'] == 'True':
        return GOOD2BAD[3]
    if f['tls_version'] == '1.3':
        return GOOD2BAD[0]
    if f['tls_version'] == '1.2':
        return GOOD2BAD[1]
    return GOOD2BAD[2]


def seconds_formatter(ax):
    """Plain tick labels, with the unit on the last visible tick."""
    lo, hi = ax.get_xlim()
    ticks = [t for t in ax.get_xticks() if lo <= t <= hi]
    last = max(ticks)
    ax.set_xticks(ticks)
    ax.set_xticklabels([f'{t:.0f} s' if t == last else f'{t:.0f}' for t in ticks])


def update_timelines():
    flows = rows(CTRL / 'flows.csv')
    # apple-tv (six servers) fills the left half; the three smaller timelines stack on the right
    fig = plt.figure(figsize=(TXT_W, 2.15))
    gs = fig.add_gridspec(3, 2, height_ratios=[2, 2, 1.25])
    panels = [('apple-tv', fig.add_subplot(gs[:, 0])), ('tapo-c200', fig.add_subplot(gs[0, 1])),
              ('xiaomi-cam', fig.add_subplot(gs[1, 1])), ('reolink-cam', fig.add_subplot(gs[2, 1]))]
    for dev, ax in panels:
        fl = [f for f in flows if f['device'] == dev and f['endpoint']]
        t0 = min(float(f['t0']) for f in fl)
        tmax = max(float(f['t1']) for f in fl) - t0
        order = []
        for f in sorted(fl, key=lambda f: float(f['t0'])):
            lab = SHORT.get(f['endpoint'], f['endpoint'])
            if lab not in order:
                order.append(lab)
        ypos = {lab: i for i, lab in enumerate(order[::-1])}
        big = collections.defaultdict(int)
        for f in fl:
            lab = SHORT.get(f['endpoint'], f['endpoint'])
            a, b = float(f['t0']) - t0, float(f['t1']) - t0
            # short flows stay visible: at least 0.6% of the axis, 1.5% for image transfers
            minw = tmax * (0.015 if '(image)' in lab else 0.006)
            ax.barh(ypos[lab], max(b - a, minw), left=a, height=0.56, color=channel_color(f), linewidth=0)
            big[lab] += int(f['bytes_down']) + int(f['bytes_up'])
        for lab, v in big.items():
            if v > 1e6:
                end = max(float(f['t1']) - t0 for f in fl if SHORT.get(f['endpoint'], f['endpoint']) == lab)
                txt = f'{v / 1e9:.2f} GB' if v > 1e9 else f'{v / 1e6:.1f} MB'
                ax.text(max(end, tmax * 0.015) + tmax * 0.02, ypos[lab], txt, va='center', fontsize=FS_NOTE,
                        color=INK)
        ax.set_yticks(list(ypos.values()))
        ax.set_yticklabels(list(ypos.keys()))
        ax.set_xlim(-tmax * 0.01, tmax * 1.16)
        ax.set_ylim(-0.6, len(order) - 0.4)
        ax.xaxis.set_major_locator(matplotlib.ticker.MaxNLocator(nbins=6, steps=[1, 2, 2.5, 5, 10]))
        seconds_formatter(ax)
        vgrid(ax)
        ax.tick_params(axis='y', length=0)
        ax.set_title(dev, loc='left', fontweight='bold')
    panels[0][1].set_xlabel('time since the first update flow')
    panels[-1][1].set_xlabel('time since the first update flow')
    handles = [Patch(color=GOOD2BAD[0], label='TLS 1.3'), Patch(color=GOOD2BAD[1], label='TLS 1.2'),
               Patch(color=GOOD2BAD[2], label='HTTP (unencrypted)'),
               Patch(color=GOOD2BAD[3], label='local push (unencrypted)')]
    fig.legend(handles=handles, loc='outside lower center', ncol=4)
    save(fig, 'update_timelines')


# ---- 4. offered vs negotiated ------------------------------------------------------
def offered_negotiated():
    ctrl = rows(CTRL / 'flows.csv')
    retro = rows(RETRO / 'update_flows.csv')
    groups = collections.OrderedDict()

    def add(label, cfg, neg_label, neg_ver):
        key = (label, cfg)
        g = groups.setdefault(key, dict(label=label, cfg=cfg, neg=collections.Counter()))
        g['neg'][(neg_ver, neg_label)] += 1

    names = {'apple-tv': 'Apple (apple-tv, homepod)', 'homepod': 'Apple (apple-tv, homepod)'}
    xiaomi = {'fk-res-abroad-cdn.home.mi.com': 'xiaomi-cam, image server', 'de.ots.io.mi.com': 'xiaomi-cam, device channel'}
    for f in ctrl:
        if f['endpoint'] and f['offered_config'] and f['suite_label']:
            lab = xiaomi.get(f['endpoint'], names.get(f['device'], f['device']))
            add(lab, f['offered_config'], f['suite_label'], f['tls_version'])
    amazon = {'echodot', 't-echodot', 'echoplus', 'echospot', 'firetv', 'cloudcam'}
    for f in retro:
        if f['offered_config'] and f['label']:
            codes = f['offered_config'].split(',')
            if f['device'] in amazon:
                lab = 'Amazon devices' if '0005' in codes else 'echodot, second client'
            elif f['device'] == 'appletv':
                lab = 'appletv, offers TLS 1.3' if '1301' in codes else 'appletv, TLS 1.2 only'
            else:
                lab = f['device'].replace('t-smartthings-hub', 'smartthings-hub')
            add(lab + ' (2019)', f['offered_config'], f['label'], f['tls_version'])
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from tls_classes import label as cs_label  # noqa: E402
    items = []
    for (lab, cfg), g in groups.items():
        codes = [c for c in cfg.split(',') if c != 'GREASE']
        cnt = collections.Counter(cs_label(c) for c in codes)
        items.append((lab, cnt, g['neg']))
    # merge identical labels with identical composition
    merged = collections.OrderedDict()
    for lab, cnt, neg in items:
        k = (lab, tuple(cnt[c] for c in ('recommended', 'secure', 'weak', 'insecure')))
        if k in merged:
            merged[k][1].update(neg)
        else:
            merged[k] = [cnt, collections.Counter(neg)]
    entries = [(k[0], v[0], v[1]) for k, v in merged.items()]
    recent = [e for e in entries if not e[0].endswith('(2019)')]
    old = [e for e in entries if e[0].endswith('(2019)')]
    recent.sort(key=lambda e: e[0])
    old.sort(key=lambda e: e[0])
    entries = recent + old
    # disambiguate duplicate labels (e.g. two configurations of one device)
    seen = collections.Counter(e[0] for e in entries)
    idx = collections.Counter()
    fig, ax = plt.subplots(figsize=(COL_W, 0.143 * (len(entries) + 2) + 0.6))
    cats = ['recommended', 'secure', 'weak', 'insecure']
    ylabels = []
    ypos, y = [], len(entries) + 1
    for i in range(len(entries)):
        if i == 0 or i == len(recent):
            y -= 1
        ypos.append(y)
        y -= 1
    right = blended_transform_factory(ax.transAxes, ax.transData)
    for i, (lab, cnt, neg) in enumerate(entries):
        y = ypos[i]
        if seen[lab] > 1:
            idx[lab] += 1
            lab = f'{lab} #{idx[lab]}'
        ylabels.append((y, tex(lab.replace(' (2019)', ''))))
        left = 0
        for c, col in zip(cats, GOOD2BAD):
            if cnt[c]:
                ax.barh(y, max(cnt[c] - 0.35, 0.3), left=left, height=0.66, color=col, linewidth=0)
                left += cnt[c]
        # negotiated suite (most frequent) in an aligned column right of the axes
        (ver, nl), _ = neg.most_common(1)[0]
        ax.plot([1.035], [y], marker='D', markersize=4.2, color=GOOD2BAD[cats.index(nl)], transform=right,
                markeredgecolor='white', markeredgewidth=0.6, clip_on=False)
        ax.text(1.07, y, f'{ver} {nl}', va='center', ha='left', fontsize=FS_NOTE, color=INK, transform=right)
    for yy, head in ((ypos[0] + 1, 'Our captures'), (ypos[len(recent)] + 1, '2019 traces')):
        fig_left_text(ax, yy, head, fontsize=FS, color=INK, fontweight='bold', va='center')
    ax.text(1.035, ypos[0] + 1, 'negotiated', va='center', ha='left', fontsize=FS_NOTE, color=INK2, transform=right)
    ax.set_ylim(min(ypos) - 0.7, ypos[0] + 1.6)
    ax.set_yticks([y for y, _ in ylabels])
    ax.set_yticklabels([lab for _, lab in ylabels])
    ax.set_xlim(0, 88)
    ax.set_xticks([0, 20, 40, 60, 80])
    ax.set_xlabel('cipher suites offered in the ClientHello')
    vgrid(ax)
    ax.tick_params(axis='y', length=0)
    handles = [Patch(color=col, label=c) for c, col in zip(cats, GOOD2BAD)]
    fig.legend(handles=handles, loc='outside upper center', ncol=4)
    save(fig, 'offered_negotiated')


# ---- 5. leaf certificate lifetimes -------------------------------------------------
def leaf_lifetimes():
    ctrl = rows(CTRL / 'leaf_certs.csv')
    retro = [r for r in rows(RETRO / 'leaf_certs.csv') if r['role'] == 'server']
    private = ('TP-LINK CA', 'STCA', 'Honeywell')
    pts = []
    short = {'n-device-api.tplinkcloud.com': 'TP-Link device API', 'security-app-eu.eufylife.com': '*.eufylife.com'}
    for r in ctrl:
        pts.append(('recent', short.get(r['endpoint'], r['endpoint']), int(r['validity_days']), r['issuer'], r['key']))
    for r in retro:
        pts.append(('2019', r['endpoint'], int(r['validity_days']), r['issuer'], r['key']))
    pts.sort(key=lambda p: (p[0] == '2019', p[2]))
    n_recent = sum(1 for p in pts if p[0] != '2019')
    # y positions with a gap row for each group header
    ypos, y = [], len(pts) + 1
    for i, p in enumerate(pts):
        if i == 0 or i == n_recent:
            y -= 1
        ypos.append(y)
        y -= 1
    fig, ax = plt.subplots(figsize=(COL_W, 0.139 * (len(pts) + 2) + 0.6))
    for (ds, ep, days, iss, key), y in zip(pts, ypos):
        priv = any(iss.startswith(p) for p in private)
        col = ORANGE if priv else BLUE
        weak = key == 'RSA-1024'
        ax.plot([days], [y], marker='X' if weak else 'o', markersize=6 if weak else 4.8, color=col,
                markeredgecolor='white', markeredgewidth=0.6, linestyle='none')
        txt = f'{days / 365.25:.0f} y' if days > 1000 else f'{days} d'
        ax.text(days * 1.13, y, txt + (', RSA-1024' if weak else ''), va='center', fontsize=FS_NOTE, color=INK)
    ax.set_yticks(ypos)
    ax.set_yticklabels([p[1] for p in pts])
    top = max(ypos) + 1
    fig_left_text(ax, top, 'Our captures', fontsize=FS, color=INK, fontweight='bold', va='center')
    fig_left_text(ax, ypos[n_recent] + 1, '2019 traces', fontsize=FS, color=INK, fontweight='bold', va='center')
    ax.set_xscale('log')
    ax.set_xlim(200, 40000)
    ax.set_ylim(min(ypos) - 0.7, top + 0.6)
    ax.set_xticks([365, 730, 1825, 3650, 7300])
    ax.set_xticklabels(['1 y', '2 y', '5 y', '10 y', '20 y'])
    ax.xaxis.set_minor_locator(matplotlib.ticker.NullLocator())
    for lim, lab in ((398, '398 d'), (825, '825 d')):
        ax.axvline(lim, color=MUTED, linewidth=0.7, linestyle=(0, (3, 2)))
        ax.text(lim * 1.05, top, lab, fontsize=FS_NOTE, color=INK2, va='center')
    vgrid(ax)
    ax.tick_params(axis='y', length=0)
    ax.set_xlabel('validity period (log scale)')
    handles = [Line2D([], [], marker='o', color='none', markerfacecolor=BLUE, markeredgecolor='white',
                      markersize=5.5, label='public or Apple CA'),
               Line2D([], [], marker='o', color='none', markerfacecolor=ORANGE, markeredgecolor='white',
                      markersize=5.5, label="vendor's own CA"),
               Line2D([], [], marker='X', color='none', markerfacecolor=MUTED, markeredgecolor='white',
                      markersize=6.5, label='80-bit key (RSA-1024)')]
    fig.legend(handles=handles, loc='outside upper center', ncol=3)
    save(fig, 'leaf_lifetimes')


# ---- 6. channel x image ------------------------------------------------------------
def channel_image():
    # Image channel from flows.csv / Table 3; image protection from the static image analysis
    # (data/derived/image_protection/integrity_tiers.csv) and Apple's documentation.
    cols = ['local push\n(cleartext)', 'HTTP\n(cleartext)', 'TLS 1.2', 'TLS 1.3', 'no image\nseen']
    rows_ = ['checksum\nonly', 'no signature\nfound', 'unknown', 'signed', 'signed and\nauthorized\nper device']
    place = {(cols[0], rows_[1]): ['reolink-cam'],
             (cols[1], rows_[3]): ['tapo-c100', 'tapo-c200'],
             (cols[2], rows_[2]): ['eufy-cam', 'xiaomi-cam'],
             (cols[3], rows_[4]): ['apple-tv', 'homepod'],
             (cols[4], rows_[0]): ['d-link-cam'],
             (cols[4], rows_[3]): ['fire-tv'],
             (cols[4], rows_[2]): ['sony-tv']}
    fig, ax = plt.subplots(figsize=(COL_W, 1.98))
    for i, c in enumerate(cols):
        for j, r in enumerate(rows_):
            y = len(rows_) - 1 - j
            danger = (i <= 1 and j <= 1)
            ax.add_patch(plt.Rectangle((i + 0.03, y + 0.05), 0.94, 0.9,
                                       facecolor='#fbe3dd' if danger else '#f4f4f1', edgecolor='none'))
            devs = place.get((c, r), [])
            for k, d in enumerate(devs):
                dy = (0.2 if k == 0 else -0.2) if len(devs) == 2 else 0
                ax.text(i + 0.5, y + 0.5 + dy, d, ha='center', va='center', fontsize=FS_NOTE, color=INK)
    ax.set_xlim(0, len(cols))
    ax.set_ylim(0, len(rows_))
    ax.set_xticks([i + 0.5 for i in range(len(cols))])
    ax.set_xticklabels(cols, fontsize=FS_TICK, color=INK)
    ax.set_yticks([len(rows_) - 1 - j + 0.5 for j in range(len(rows_))])
    ax.set_yticklabels(rows_, fontsize=FS_TICK)
    ax.tick_params(length=0)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.xaxis.tick_top()
    ax.set_xlabel('how the image reached the device')
    ax.xaxis.set_label_position('top')
    save(fig, 'channel_image')


# ---- 7. entropy by channel ---------------------------------------------------------
def entropy_by_channel():
    data = rows(CTRL / 'entropy_by_channel.csv')
    groups = [('TLS 1.3', GOOD2BAD[0]), ('TLS 1.2', GOOD2BAD[1]), ('HTTP, image or asset', GOOD2BAD[2]),
              ('local push', GOOD2BAD[3]), ('HTTP, check or metadata', GOOD2BAD[2])]
    fig, ax = plt.subplots(figsize=(COL_W, 1.92))
    lo, hi = 0.2, 1.02
    ax.axvspan(lo, 0.4, color='#f4f4f1', linewidth=0)
    ax.axvspan(0.8, hi, color='#eef3fb', linewidth=0)
    for x in (0.4, 0.8):
        ax.axvline(x, color=MUTED, linewidth=0.7, linestyle=(0, (3, 2)))
    rnd = random.Random(7)
    right = blended_transform_factory(ax.transAxes, ax.transData)
    for yi, (g, col) in enumerate(groups[::-1]):
        pts = [r for r in data if r['group'] == g]
        for ds, marker, alpha in (('2019', '^', 0.35), ('ours', 'o', 0.9)):
            xs = [float(r['entropy']) for r in pts if r['dataset'] == ds]
            ys = [yi + rnd.uniform(-0.2, 0.2) for _ in xs]
            if xs:
                ax.scatter(xs, ys, s=13 if ds == 'ours' else 8, marker=marker, color=col, alpha=alpha,
                           linewidths=0.3, edgecolors='white', zorder=3)
        n_ours = sum(1 for r in pts if r['dataset'] == 'ours')
        n_19 = sum(1 for r in pts if r['dataset'] == '2019')
        ax.text(1.07, yi, f'{n_ours} / {n_19:,}', va='center', ha='left', fontsize=FS_NOTE, color=INK,
                transform=right)
    # band names and the flow-count header sit above the plot area, clear of the data
    top = ax.get_xaxis_transform()
    for x, lab in ((0.3, 'likely\nunencrypted'), (0.6, 'undetermined'), (0.895, 'encrypted or\ncompressed')):
        ax.text(x, 1.02, lab, ha='center', va='bottom', fontsize=FS_NOTE, color=INK2, transform=top,
                linespacing=1.0)
    ax.text(1.07, 1.02, 'flows\nours / 2019', ha='left', va='bottom', fontsize=FS_NOTE, color=INK2,
            transform=ax.transAxes, linespacing=1.0)
    ax.set_yticks(range(len(groups)))
    ax.set_yticklabels([g for g, _ in groups[::-1]])
    ax.set_xlim(lo, hi)
    ax.set_ylim(-0.55, len(groups) - 0.45)
    ax.set_xticks([0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0])
    ax.set_xticklabels(['0.2', '', '0.4', '', '0.6', '', '0.8', '', '1.0'])
    ax.set_xlabel('normalized Shannon entropy of the flow payload')
    ax.tick_params(axis='y', length=0)
    handles = [Line2D([], [], marker='o', color='none', markerfacecolor=INK2, markeredgecolor='white',
                      markersize=4.5, label='our lab'),
               Line2D([], [], marker='^', color='none', markerfacecolor=INK2, markeredgecolor='white',
                      markersize=4.5, alpha=0.6, label='2019 traces')]
    fig.legend(handles=handles, loc='outside lower center', ncol=2)
    save(fig, 'entropy_by_channel')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--only')
    args = ap.parse_args()
    funcs = dict(traffic_composition=traffic_composition, keyword_baseline=keyword_baseline,
                 update_timelines=update_timelines, offered_negotiated=offered_negotiated,
                 leaf_lifetimes=leaf_lifetimes, channel_image=channel_image,
                 entropy_by_channel=entropy_by_channel)
    for k, f in funcs.items():
        if args.only and k != args.only:
            continue
        if k == 'keyword_baseline' and not (RETRO / 'keyword_baseline.csv').exists():
            print('skip keyword_baseline (run keyword_baseline.py first)')
            continue
        f()


if __name__ == '__main__':
    main()
