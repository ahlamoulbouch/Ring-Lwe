import numpy as np
from she import RLWE, Rq
import time
import matplotlib.pyplot as plt


def security_level(n, q):
    """Calculer la sécurité estimée basée sur n et q."""
    return int(n * np.log2(q))  # En bits


def performance_analysis(n_values, q, t, std):
    results = []

    for n in n_values:
        rlwe = RLWE(n, q, t, std)
        (sec, pub) = rlwe.generate_keys()

        # Générer un message aléatoire (binaire)
        m = Rq(np.random.randint(t, size=n), t)  # Message binaire

        # Chiffrement
        start_time = time.time()
        c = rlwe.encrypt(m, pub)
        enc_time = (time.time() - start_time) * 1000  # Temps de chiffrement en ms

        # Déchiffrement
        start_time = time.time()
        decrypted_message = rlwe.decrypt(c, sec)
        dec_time = (time.time() - start_time) * 1000  # Temps de déchiffrement en ms

        # Taille des clés
        key_size = (2 * n + n) * 8  # En bits (a0, a1, et s)

        # Niveau de sécurité (approximatif)
        estimated_security_level = security_level(n, q)  # En bits

        results.append((n, enc_time, dec_time, key_size, estimated_security_level))

    return results


def plot_security_levels(n_values, estimated_security_levels):
    """Tracer le graphe du niveau de sécurité par rapport à N."""
    plt.figure(figsize=(6, 6))
    plt.plot(n_values, estimated_security_levels, marker='o', color='g', label='Niveau de Sécurité')
    plt.title("Niveau de Sécurité en fonction de N")
    plt.xlabel("N")
    plt.ylabel("Niveau de Sécurité (bits)")
    plt.xticks(n_values)
    plt.grid()
    plt.legend()
    plt.tight_layout()
    plt.show()


if __name__ == '__main__':
    n_values = [128, 256, 512, 1024, 2048]  # Exemples de puissances de 2
    q = 4097  # Nombre premier
    t = 73  # Prime < q
    std = 5  # Écart type de la distribution gaussienne

    results = performance_analysis(n_values, q, t, std)

    # Afficher les résultats
    print("Paramètres Ring-LWE:")
    print("N\tTemps Chiffrement (ms)\tTemps Déchiffrement (ms)\tTaille des Clés (bits)\tNiveau de Sécurité (bits)")
    for n, enc_time, dec_time, key_size, estimated_security_level in results:
        print(f"{n}\t{enc_time:.2f}\t\t\t{dec_time:.2f}\t\t\t{key_size}\t\t\t{estimated_security_level}")

    # Extraire les niveaux de sécurité pour le graphe
    estimated_security_levels = [result[4] for result in results]

    # Tracer le graphe des niveaux de sécurité
    plot_security_levels(n_values, estimated_security_levels)

    # Graphique des résultats de temps de chiffrement et déchiffrement
    enc_times = [result[1] for result in results]
    dec_times = [result[2] for result in results]

    plt.figure(figsize=(12, 6))

    # Temps de chiffrement
    plt.subplot(1, 2, 1)
    plt.plot(n_values, enc_times, marker='o', color='b', label='Chiffrement')
    plt.title("Temps de Chiffrement en fonction de N")
    plt.xlabel("N")
    plt.ylabel("Temps (ms)")
    plt.xticks(n_values)
    plt.grid()
    plt.legend()

    # Temps de déchiffrement
    plt.subplot(1, 2, 2)
    plt.plot(n_values, dec_times, marker='o', color='r', label='Déchiffrement')
    plt.title("Temps de Déchiffrement en fonction de N")
    plt.xlabel("N")
    plt.ylabel("Temps (ms)")
    plt.xticks(n_values)
    plt.grid()
    plt.legend()

    plt.tight_layout()
    plt.show()
