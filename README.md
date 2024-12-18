# knight - A Versatile Bash Script for System Audits and Security Checks

## Introduzione

`knight.sh` è uno script Bash progettato per offrire strumenti pratici e potenti per amministratori di sistema e professionisti della sicurezza. Con knight puoi:

- Analizzare vulnerabilità di sistema.
- Verificare configurazioni critiche.
- Ottenere informazioni dettagliate sul sistema e molto altro.

## Funzionalità principali

1. **Analisi di vulnerabilità**: identifica possibili problemi come "Shellshock", "Dirty Cow", e altre CVE comuni.
2. **Verifica di configurazioni**: controlla file critici come `/etc/passwd`, `/etc/shadow`, e configurazioni SSH.
3. **Informazioni sul sistema**: raccoglie dettagli su utenti, shell disponibili, distribuzione Linux e architettura.
4. **Utility per Docker**: identifica container Docker, esegue scansioni e verifica configurazioni potenzialmente vulnerabili.
5. **Esposizione di cron job**: analizza i job pianificati e le configurazioni di rete.

## Esempio di menu interattivo

Quando avvii knight, viene mostrata un menu interattivo che consente di selezionare facilmente le opzioni desiderate:

```bash
       !
      .-.
    __|=|__
   (_/`-`\_)
   //\___/\
   <>/   \<>
    \|_._|/
     <_I_>
      |||
     /_|_\ 


[+] Knight-v(4.3.6) initialzing on kali at 12:40:25

[+] Choose the option number from the menu below! 

1) Sudo                             10) bash_history                    19) check_dirty_cow
2) tty_shell                        11) config_code                     20) check_CVE_2023_26604
3) passwd_shadow                    12) hidden_service_and_network      21) Shellshock_vulnerability_check
4) whoisthis                        13) NFS_shares                      22) check_CVE_2016_0728
5) capabilities                     14) search_wordpress_config         23) check_CVE_2016_1531
6) cronjobs                         15) console_clear                   24) check_CVE_2010_0426
7) keys_ssh                         16) docker-scan                     25) check-2023-22809
8) docker                           17) check_writable_dirs             26) exit
9) SU_GIDs                          18) check_logrotten

(knight@hostname)-[~/path/to/directory]~#
```

## Esecuzione dello script

Per avviare knight, assicurati che lo script abbia i permessi di esecuzione:

```bash
chmod +x knight.sh
./knight.sh
```

Puoi anche visualizzare l'help o la versione dello script utilizzando:

```bash
./knight.sh --help
./knight.sh --version
```

## Credits

Questo progetto prende spunto da:

- [vrikodar](https://github.com/vrikodar/Lemon)
- [stealthcopter](https://github.com/stealthcopter/deepce)
- [eversinc33](https://github.com/eversinc33/JailWhale)

