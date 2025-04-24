import pyshark
import subprocess
import threading
import sqlite3
import time
from collections import defaultdict
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('TrafficSniffer')


class TrafficSniffer:
    def __init__(self, interface="eth0", db_path="traffic.db"):
        self.interface = interface
        self.db_path = db_path
        self.sniffing = False
        self.thread = None
        self.process = None
        self.ip_counts = defaultdict(int)
        self.service_counts = defaultdict(int)
        self.allowed_protocols = ['tcp', 'udp', 'icmp']
        self.allowed_services = [
            'ftp_data', 'other', 'private', 'http', 'remote_job', 'name', 'netbios_ns',
            'eco_i', 'mtp', 'telnet', 'finger', 'domain_u', 'supdup', 'uucp_path', 'Z39_50',
            'smtp', 'csnet_ns', 'uucp', 'netbios_dgm', 'urp_i', 'auth', 'domain', 'ftp',
            'bgp', 'ldap', 'ecr_i', 'gopher', 'vmnet', 'systat', 'http_443', 'efs', 'whois',
            'imap4', 'iso_tsap', 'echo', 'klogin', 'link', 'sunrpc', 'login', 'kshell',
            'sql_net', 'time', 'hostnames', 'exec', 'ntp_u', 'discard', 'nntp', 'courier',
            'ctf', 'ssh', 'daytime', 'shell', 'netstat', 'pop_3', 'nnsp', 'IRC', 'pop_2',
            'printer', 'tim_i', 'pm_dump', 'red_i', 'netbios_ssn', 'rje', 'X11', 'urh_i',
            'http_8001', 'aol', 'http_2784', 'tftp_u', 'harvest'
        ]
        self.allowed_flags = ['SF', 'S0', 'REJ', 'RSTR', 'SH', 'RSTO', 'S1', 'RSTOS0', 'S3', 'S2', 'OTH']
        self.port_service_mapping = {
            20: 'ftp_data',
            21: 'ftp',
            22: 'ssh',
            23: 'telnet',
            25: 'smtp',
            43: 'whois',
            53: 'domain',
            80: 'http',
            88: 'kerberos',
            110: 'pop_3',
            115: 'sftp',
            119: 'nntp',
            123: 'ntp_u',
            143: 'imap4',
            161: 'snmp',
            194: 'IRC',
            389: 'ldap',
            443: 'http_443',
            445: 'microsoft_ds',
            465: 'smtp',
            514: 'shell',
            515: 'printer',
            587: 'smtp',
            631: 'ipp',
            636: 'ldap',
            993: 'imap4',
            995: 'pop_3',
            1080: 'socks',
            1433: 'ms-sql-s',
            1521: 'oracle',
            2049: 'nfs',
            3306: 'mysql',
            3389: 'ms-wbt-server',
            5432: 'postgresql',
            5900: 'vnc',
            6000: 'X11',
            8000: 'http_8001',
            8080: 'http',
            8443: 'https-alt',
            8888: 'http_alt',
            9000: 'cslistener',
            27017: 'mongodb',
        }

        self._init_db()
        logger.info(f"Initialized TrafficSniffer on interface {interface}")

    def _init_db(self):
        """Инициализация таблицы в базе данных"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS traffic (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    protocol TEXT,
                    bytes INTEGER,
                    service TEXT,
                    flag TEXT,
                    count INTEGER,
                    srv_count INTEGER,
                    dst_host_count INTEGER,
                    dst_host_srv_count INTEGER
                )
            """)
            conn.commit()

    def normalize_protocol(self, protocol):
        """Нормализация протокола только к разрешённым значениям"""
        protocol = protocol.lower() if protocol else 'tcp'
        return protocol if protocol in self.allowed_protocols else 'tcp'

    def normalize_service(self, port, protocol):
        """Нормализация сервиса только к разрешённым значениям"""
        try:
            port = int(port)
            service = self.port_service_mapping.get(port, 'other')
        except (ValueError, TypeError):
            service = 'other'

        return service if service in self.allowed_services else 'other'

    def normalize_flag(self, tcp_layer):
        """Нормализация флагов только к разрешённым значениям"""
        if not hasattr(tcp_layer, 'flags'):
            return 'OTH'

        flags = tcp_layer.flags

        # Анализ флагов TCP
        if isinstance(flags, str):
            if '0x' in flags:
                try:
                    flags_int = int(flags.split('0x')[1], 16)
                    if flags_int == 0x02:
                        return 'S0'
                    elif flags_int == 0x12:
                        return 'S1'
                    elif flags_int == 0x10:
                        return 'SF'
                    elif flags_int == 0x11:
                        return 'SF'
                    elif flags_int == 0x04:
                        return 'RSTO'
                    elif flags_int == 0x14:
                        return 'RSTR'
                except:
                    pass
            elif 'SYN' in flags and 'ACK' in flags:
                return 'S1'
            elif 'SYN' in flags:
                return 'S0'
            elif 'ACK' in flags:
                return 'SF'
            elif 'RST' in flags and 'ACK' in flags:
                return 'RSTR'
            elif 'RST' in flags:
                return 'RSTO'
            elif 'FIN' in flags:
                return 'SF'

        # Проверка отдельных флагов
        if hasattr(tcp_layer, 'syn') and tcp_layer.syn == '1':
            if hasattr(tcp_layer, 'ack') and tcp_layer.ack == '1':
                return 'S1'
            return 'S0'
        elif hasattr(tcp_layer, 'ack') and tcp_layer.ack == '1':
            return 'SF'
        elif hasattr(tcp_layer, 'rst') and tcp_layer.rst == '1':
            if hasattr(tcp_layer, 'ack') and tcp_layer.ack == '1':
                return 'RSTR'
            return 'RSTO'
        elif hasattr(tcp_layer, 'fin') and tcp_layer.fin == '1':
            return 'SF'

        return 'OTH'

    def packet_handler(self, packet):
        try:
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S')

            if not hasattr(packet, 'ip'):
                logger.debug("Packet has no IP layer, skipping")
                return

            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            bytes_size = int(packet.length) if hasattr(packet, 'length') else 0

            # Определение протокола
            protocol = self.normalize_protocol(
                getattr(packet, 'transport_layer', 'tcp')
            )

            # Определение сервиса и флагов
            service = "other"
            flag = "OTH"

            if hasattr(packet, 'tcp'):
                dport = getattr(packet.tcp, 'dstport', '0')
                service = self.normalize_service(dport, 'tcp')
                flag = self.normalize_flag(packet.tcp)

            elif hasattr(packet, 'udp'):
                dport = getattr(packet.udp, 'dstport', '0')
                service = self.normalize_service(dport, 'udp')

            elif hasattr(packet, 'icmp'):
                service = "eco_i"
                protocol = "icmp"

            self.ip_counts[src_ip] += 1
            self.service_counts[(dst_ip, service)] += 1

            self.save_to_db(
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=protocol,
                bytes=bytes_size,
                service=service,
                flag=flag,
                count=self.ip_counts[src_ip],
                srv_count=self.service_counts[(dst_ip, service)],
                dst_host_count=len(set(self.ip_counts.keys())),
                dst_host_srv_count=len(set(self.service_counts.keys()))
            )

        except Exception as e:
            logger.error(f"Error processing packet: {e}", exc_info=True)

    def save_to_db(self, **kwargs):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO traffic VALUES (
                        NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                    )
                """, (
                    kwargs['timestamp'],
                    kwargs['src_ip'],
                    kwargs['dst_ip'],
                    kwargs['protocol'],
                    kwargs['bytes'],
                    kwargs['service'],
                    kwargs['flag'],
                    kwargs['count'],
                    kwargs['srv_count'],
                    kwargs['dst_host_count'],
                    kwargs['dst_host_srv_count']
                ))
                conn.commit()
        except Exception as e:
            logger.error(f"DB Error: {e}")

    def sniff_with_pyshark(self):
        """Сниффинг с использованием pyshark"""
        try:
            logger.info(f"Starting pyshark capture on {self.interface}")
            capture = pyshark.LiveCapture(
                interface=self.interface,
                display_filter='ip',
                use_json=True
            )

            for packet in capture.sniff_continuously():
                if not self.sniffing:
                    logger.info("Stopping capture by user request")
                    break
                self.packet_handler(packet)

        except Exception as e:
            logger.error(f"Pyshark capture error: {e}", exc_info=True)
            raise

    def sniff_with_tcpdump(self):
        """Сниффинг с использованием tcpdump"""
        try:
            self.process = subprocess.Popen(
                ['tcpdump', '-i', self.interface, '-w', '-'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            capture = pyshark.FileCapture(
                self.process.stdout,
                use_json=True,
                include_raw=True
            )

            for packet in capture:
                if not self.sniffing:
                    break
                self.packet_handler(packet)

        except Exception as e:
            logger.error(f"Tcpdump error: {e}")
        finally:
            if self.process:
                self.process.terminate()

    def start_sniffing(self, method='pyshark'):
        """Запуск сниффинга с указанным методом"""
        if not self.sniffing:
            self.sniffing = True
            target = self.sniff_with_pyshark if method == 'pyshark' else self.sniff_with_tcpdump
            self.thread = threading.Thread(target=target)
            self.thread.start()
            logger.info(f"Started sniffing using {method} method")

    def stop_sniffing(self):
        """Остановка сниффинга"""
        self.sniffing = False
        logger.info("Stopping sniffer...")
        if self.process:
            self.process.terminate()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2)
        logger.info("Sniffer stopped")


if __name__ == "__main__":
    sniffer = TrafficSniffer(interface="eth0")
    try:
        sniffer.start_sniffing(method='pyshark')
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        sniffer.stop_sniffing()