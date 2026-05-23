# Changelog - Rust Probe

## v0.6.0 - Melhorias no Sistema de Detecção (2026-05-23)

### Melhorias Implementadas

#### 1. Sistema de Anomalias Detalhadas
- ✅ Novo módulo `core/anomaly.rs` com tipos estruturados de anomalias
- ✅ Classificação por severidade: Info, Baixa, Média, Alta, Crítica
- ✅ Detalhamento completo no output: tipo, camada, descrição e detalhes
- ✅ Cada anomalia agora informa ONDE foi detectada (Passive, HID, CDC, Timing, etc.)

#### 2. Weighted Scoring System
- ✅ Substituição do sistema heurístico por pontuação ponderada
- ✅ Impacto no score baseado na severidade da anomalia:
  - Info: 0% de impacto
  - Baixa: 2% de redução
  - Média: 5% de redução
  - Alta: 10% de redução
  - Crítica: 20% de redução
- ✅ Bônus para fabricantes confiáveis (+10%)
- ✅ Bônus para detecção de stack USB (+5%)

#### 3. Detecção de USB Hubs
- ✅ Identificação automática de USB Hubs legítimos
- ✅ VIDs conhecidos: 0x1D6B (Linux Foundation), 0x8087 (Intel), 0x0BDA (Realtek)
- ✅ Detecção por classe USB (0x09 = Hub)
- ✅ Hubs são automaticamente classificados como "Genuíno" sem falsos positivos

#### 4. Redução de Falsos Positivos
- ✅ Lista expandida de fabricantes confiáveis (30+ marcas)
- ✅ Anomalias de baixa severidade não afetam significativamente o score
- ✅ Múltiplos fatores considerados antes de classificar como suspeito
- ✅ Dispositivos legítimos com anomalias menores são corretamente identificados

#### 5. Classificação Inteligente de Trust Level
- ✅ Confiança ≥ 90%: Genuíno
- ✅ Confiança ≥ 75%: Genuíno (se fabricante confiável) ou Placa Modificada
- ✅ Confiança ≥ 50%: Placa Modificada
- ✅ Confiança ≥ 30%: VID/PID Falsificado
- ✅ Confiança < 30%: Modificação Profunda
- ✅ Anomalias críticas = classificação imediata como suspeito

### Exemplo de Output Melhorado

```
[!] Detalhamento de Anomalias:
  1. [BAIXA] [Passive] String de fabricante ausente
  2. [BAIXA] [Passive] String de produto ausente
  3. [BAIXA] [Passive] Numero de serie ausente
```

Agora o usuário sabe EXATAMENTE:
- Qual a severidade da anomalia
- Em qual camada foi detectada
- O que foi detectado

### Próximos Passos (v0.7.0)

#### Banco de Perfis
- [ ] Carregar perfis de `profiles/profiles.json`
- [ ] Matching de dispositivos conhecidos
- [ ] Fingerprint persistente (device_signature)
- [ ] Cache de dispositivos já analisados

#### Melhorias Adicionais
- [ ] Exportação de relatórios em JSON
- [ ] Modo de monitoramento contínuo
- [ ] Interface web para visualização
- [ ] Machine learning para detecção de padrões

### Arquivos Modificados

- `Rust_Probe/src/core/anomaly.rs` (NOVO)
- `Rust_Probe/src/core/mod.rs`
- `Rust_Probe/src/engine/confidence_engine_v2.rs` (NOVO)
- `Rust_Probe/src/engine/device_analyzer.rs`
- `Rust_Probe/src/engine/mod.rs`
- `Rust_Probe/src/main.rs`
- `README.md` (removidos emojis)

### Problemas Resolvidos

1. ✅ USB Hubs (VID 0x1D6B) não são mais marcados como modificados
2. ✅ Dispositivos legítimos com anomalias menores são corretamente classificados
3. ✅ Output agora detalha QUAIS anomalias foram detectadas
4. ✅ Sistema de scoring mais robusto e menos propenso a falsos positivos
5. ✅ Fabricantes confiáveis recebem tratamento adequado
