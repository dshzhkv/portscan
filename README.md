# portscan

using (linux):

`sudo python3 portscan.py 1.1.1.1 [OPTIONS] IP_ADDRESS [{tcp|udp}[/[PORT|PORT-PORT],...]]`

Опции `[OPTIONS]` следующие:

* `--timeout` — таймаут ожидания ответа (по умолчанию 2с)
* `-v, --verbose` — подробный режим (по умолчанию False)
* `-g, --guess` — определение протокола прикладного уровня (по умолчанию False)


example:
`sudo python3 portscan.py 1.1.1.1 tcp/80 tcp/12000-12500 udp/3000-3100,3200,3300-4000`

