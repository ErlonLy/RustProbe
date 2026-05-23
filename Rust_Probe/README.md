# Rust Probe - Advanced Hardware Authentication Analyzer

Analisador avançado de autenticidade de hardware para detecção de dispositivos de desenvolvimento (Arduino, ESP32-S3, Teensy) e periféricos modificados, utilizando técnicas similares aos sistemas anti-cheat modernos.

## Características Principais

### Detecção Avançada
- **Arduino**: Todos os modelos oficiais (Uno, Mega, Leonardo, Micro, Zero, Nano 33 IoT)
- **ESP32**: Suporte completo para ESP32-S3, ESP32-S2, ESP32-C3 com USB nativo
- **Teensy**: Detecção de placas PJRC Teensy 2.0, 3.x, 4.x, LC
- **Chips Clone**: CH340, CP2102, PL2303, FTDI

### Técnicas Anti-Cheat Implementadas
1. **Análise de Coexistência de Interfaces**: Detecta combinações suspeitas (HID + CDC)
2. **Verificação de Polling Rate**: Identifica taxas anormais para periféricos gaming
3. **Análise de bcdDevice**: Verifica assinaturas de bootloaders
4. **Inspeção de Número de Série**: Detecta padrões genéricos e assinaturas de desenvolvimento
5. **Análise de Timing**: Mede consistência de resposta do hardware
6. **Verificação de Descritores USB**: Detecta anomalias em configurações
7. **Análise de Consumo de Energia**: Identifica padrões anormais
8. **Assinatura de Firmware**: Extrai e analisa padrões únicos
9. **Análise de Memória de Descritores**: Detecta emulação através de variação de timing

### Redução de Falsos Positivos
- Lista de fabricantes legítimos (Logitech, Microsoft, Razer, ASUS, Corsair, etc.)
- Análise contextual de interfaces USB
- Sistema de confiança baseado em múltiplos fatores
- Verificação cruzada de VID/PID com características de hardware
- Filtragem inteligente de periféricos genuínos

## Instalação

### Pré-requisitos

**Windows:**
```bash
# Instalar drivers libusb
# Baixe em: https://github.com/libusb/libusb/releases
# Ou use Zadig: https://zadig.akeo.ie/
```

**Linux:**
```bash
sudo apt-get install libusb-1.0-0-dev
```

**macOS:**
```bash
brew install libusb
```

### Compilação

```bash
cd Rust_Probe
cargo build --release
```

## Uso

### Modo Normal
```bash
cargo run --release
```

### Modo Debug (mostra todos os dispositivos USB)
```bash
cargo run --release -- --debug
```

## Níveis de Confiança

| Nível | Descrição | Cor |
|-------|-----------|-----|
| **GENUÍNO** | Dispositivo autêntico sem modificações | Verde |
| **PLACA MODIFICADA** | Hardware oficial com pequenas alterações | Amarelo |
| **VID/PID FALSIFICADO** | Identificadores USB adulterados | Vermelho |
| **MODIFICAÇÃO PROFUNDA** | Bootloader e descritores completamente alterados | Vermelho Brilhante |
| **DESCONHECIDO** | Não foi possível determinar autenticidade | Branco |

## Exemplo de Saída

```
======================================================================
Dispositivo Detectado: Bus 1 Device 5
======================================================================

Informacoes Basicas:
  VID:PID       : 0x303A:0x1001
  Fabricante    : Espressif Systems
  Produto       : ESP32-S3 USB JTAG/Serial
  Serial        : 1234567890ABCDEF

Analise de Confianca:
  Nivel         : VID/PID FALSIFICADO
  Confianca     : 35.0%

Flags Detectadas:
  - Placa de desenvolvimento ESP32 detectada
  - VID oficial Espressif Systems confirmado
  - ESP32-S3 identificado no descritor de produto
  - Configuração USB dupla detectada (2 interfaces) - característica ESP32-S3

Analise Profunda (Estilo Anti-Cheat):
  Versao USB          : 2.0
  Versao Dispositivo  : 1.0
  Configuracoes       : 1
  Interfaces          : 2
  Endpoints           : 4
  Consumo Maximo      : 500 mA
  [OK] Timing de resposta normal
  [OK] Consumo de energia normal
  Assinatura Firmware : 8:15:16:
======================================================================
```

## Tecnologias Utilizadas

- **Rust**: Linguagem de programação principal
- **rusb**: Biblioteca para comunicação USB
- **colored**: Formatação colorida de terminal
- **serde**: Serialização de dados

## Estrutura do Projeto

```
Rust_Probe/
├── src/
│   ├── main.rs                 # Ponto de entrada
│   ├── device_analyzer.rs      # Lógica de análise profunda
│   ├── device_database.rs      # Base de dados de VID/PID
│   ├── trust_evaluator.rs      # Sistema de avaliação de confiança
│   └── report_generator.rs     # Geração de relatórios
├── Cargo.toml
└── README.md
```

## Detecção de ESP32-S3

O sistema possui detecção especializada para ESP32-S3:

- **VID Oficial Espressif**: 0x303A
- **PID ESP32-S3**: 0x1001 (USB JTAG/Serial)
- **Configuração USB Dupla**: Detecta interfaces múltiplas características do S3
- **Chips Clone**: Identifica CP2102 e CH340 usados em placas genéricas

## Como Funciona a Detecção Anti-Cheat

### 1. Análise de Interface
O sistema verifica combinações suspeitas de interfaces USB. Arduinos emuladores frequentemente apresentam HID + CDC simultaneamente, o que é raro em periféricos legítimos.

### 2. Timing Analysis
Mede a consistência de resposta do hardware. Emuladores de software apresentam alta variação de timing, enquanto hardware real é consistente.

### 3. Polling Rate
Periféricos gaming genuínos usam polling rate de 1ms (bInterval=1). Arduinos modificados geralmente usam 4ms ou mais.

### 4. Assinatura de Firmware
Extrai padrões únicos dos descritores de string do dispositivo, criando uma "impressão digital" do firmware.

### 5. Análise de Consumo
Verifica se o consumo de energia declarado é compatível com o tipo de dispositivo.

## Contribuindo

Contribuições são bem-vindas! Por favor:
1. Fork o projeto
2. Crie uma branch para sua feature (`git checkout -b feature/NovaFuncionalidade`)
3. Commit suas mudanças (`git commit -m 'Adiciona nova funcionalidade'`)
4. Push para a branch (`git push origin feature/NovaFuncionalidade`)
5. Abra um Pull Request

## Licença

Este projeto está sob a licença MIT. Veja o arquivo LICENSE para mais detalhes.

## Aviso Legal

Esta ferramenta é destinada apenas para fins educacionais e de segurança. O uso para fins maliciosos ou não autorizados é estritamente proibido. Os desenvolvedores não se responsabilizam pelo uso indevido desta ferramenta.

## Roadmap

- [ ] Suporte para Raspberry Pi Pico
- [ ] Detecção de BadUSB
- [ ] Análise de tráfego USB em tempo real
- [ ] Interface gráfica (GUI)
- [ ] Exportação de relatórios em JSON/XML
- [ ] Modo de monitoramento contínuo
- [ ] Integração com sistemas anti-cheat existentes
- [ ] Detecção de DMA (Direct Memory Access) devices
- [ ] Análise de latência de resposta USB

## Troubleshooting

### "Erro ao inicializar contexto USB"
- Instale os drivers libusb usando Zadig (Windows)
- Verifique se o dispositivo USB está conectado
- Execute com privilégios de administrador

### "Não foi possível abrir o dispositivo para leitura"
- Feche o Arduino IDE e Serial Monitor
- Reinstale os drivers USB
- Verifique permissões do dispositivo (Linux: adicione usuário ao grupo plugdev)

### Dispositivo não detectado
- Verifique se o dispositivo aparece no Gerenciador de Dispositivos (Windows) ou lsusb (Linux)
- Tente um cabo USB diferente
- Pressione o botão de reset do Arduino

## Referências

- USB Specification: https://www.usb.org/documents
- Arduino VID/PID List: https://github.com/arduino/Arduino
- ESP32 USB: https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/usb-otg-console.html
- rusb Documentation: https://docs.rs/rusb/
- Riot Vanguard Anti-Cheat: https://technology.riotgames.com/news/riots-approach-anti-cheat

## Contato

Para questões, sugestões ou reportar bugs, abra uma issue no repositório do projeto.
