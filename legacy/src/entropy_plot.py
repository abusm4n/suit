import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import os

#path = os.path.expanduser("~/update_traffic/controlled/entropy/tapo.csv")
#path = os.path.expanduser("~/update_traffic/controlled/entropy/dlink.csv")
#path = os.path.expanduser("~/update_traffic/controlled/entropy/eufy.csv")
#path = os.path.expanduser("~/update_traffic/controlled/entropy/eufy.csv")
path = os.path.expanduser("~/update_traffic/controlled/entropy/xiaomi.csv")



df = pd.read_csv(path, sep=",")

# Remove negative entropy values
for col in ["entropy_shannon", "entropy_renyi", "entropy_tsallis"]:
    df[col] = df[col].mask(df[col] < 0, np.nan)

plt.figure(figsize=(10, 4))

plt.plot(df["entropy_shannon"], label="Shannon")
plt.plot(df["entropy_renyi"], label="Rényi")
plt.plot(df["entropy_tsallis"], label="Tsallis")

plt.xlabel("Xiaomi Packet Index")
plt.ylabel("Entropy")

# Grid lines (small ticks across the plot)
plt.grid(True, which='major', linestyle='--', linewidth=0.4, alpha=0.7)

plt.legend()
plt.tight_layout()

#plt.savefig("tapo_entropy_plot.pdf")
plt.savefig("xiaomi_entropy_plot.pdf")








#plt.savefig("tapo_entropy_plot.pdf",  dpi=600)

