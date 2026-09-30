import numpy as np
import matplotlib.pyplot as plt

# Data
labels = ['Encrypted', 'Unencrypted', 'Unknown']
sizes = [106, 2415, 3794]
colors = ['cyan', 'orange', 'beige']
wp = {'linewidth': 1, 'edgecolor': "green"}

def func(pct, allvalues):
    absolute = round(pct / 100. * np.sum(allvalues))
    return "{:.1f}%\n({:d})".format(pct, absolute)

# Plot
fig, ax = plt.subplots(figsize=(5, 5))
wedges, _, autotexts = ax.pie(
    sizes,
    autopct=lambda pct: func(pct, sizes),
    colors=colors,
    startangle=90,
    wedgeprops=wp,
    textprops={'color': "black"},
    shadow=True
)

ax.set_aspect('equal')  # Keep pie circular

# Legend
ax.legend(
    wedges, labels,
    #title="Traffic Type",
    loc="center left",
    bbox_to_anchor=(0.3, 0,5,  0.5)
)

# Text style
plt.setp(autotexts, size=8, weight="bold")

# Save at high resolution without borders
plt.savefig("./figures/pie_chart_high_quality.png", bbox_inches='tight', pad_inches=0, dpi=600)
plt.show()
