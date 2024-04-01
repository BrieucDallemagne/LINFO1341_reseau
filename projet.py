import pyshark as ps
import matplotlib.pyplot as plt

def plot_nbr_protocole(file):
    cap = ps.FileCapture(file)
    protocoles = {}
    for pkt in cap:
        if pkt.highest_layer == "DATA-TEXT-LINES" or pkt.highest_layer =="HTTP" or pkt.highest_layer =="ARP" or pkt.highest_layer =="ICMPV6" or pkt.highest_layer =="DATA" or pkt.highest_layer =="MDNS" or pkt.highest_layer =="_WS.MALFORMED":
            pass
        else:
            if pkt.highest_layer in protocoles:
                protocoles[pkt.highest_layer] += 1
            else:
                protocoles[pkt.highest_layer] = 1
    #transforme en pourcentage
    total = sum(protocoles.values())
    for key in protocoles:
        protocoles[key] = (protocoles[key] / total) * 100
    plt.bar(protocoles.keys(), protocoles.values())
    plt.xlabel("Protocoles")
    plt.ylabel("Pourcentage")
    plt.savefig("ajout_fichier.pdf")

    plt.show()

plot_nbr_protocole("ajout_fichier.pcapng")