---
title: "第7章：Purdueモデルに基づいたDMZ構築とJump Server導入"
---

# 第7章：Purdueモデルに基づいたDMZ構築とJump Server導入

---

## 1. はじめに

これまでの章では、RustによるOTセンサーのエミュレートやNode-REDによるHMI構築、そしてメモリ汚染攻撃とパケット解析について学んできました。

しかし、これまでの検証環境には「IT網（ホストPC）とOT網（制御システム）の間に境界が存在しない」という、実際の産業制御環境ではあり得ない構造上の課題がありました。

本章では、OTセキュリティの世界的標準設計思想である **「Purdue（パーデュー）モデル」** に準拠したセキュアな多層防御アーキテクチャへと進化させます。

さらに、単純なDockerコンテナの分割（Quick Route）に留まらず、Hyper-VとWSL2を組み合わせた本格的なハイブリッド構成を構築します。なぜあえてこの構成をとるのか、その技術的狙いについても解説します。

---

## 2. Purdueモデル（PERA）とエアギャップの崩壊

OTネットワーク設計の世界的標準である **「Purdue Enterprise Reference Architecture (PERA)」** は、ネットワークを機能とリスクに応じて階層化（Level 0 〜 5）し、厳格な境界を設ける考え方です。

* **Level 5 / 4 (Enterprise Network)**: 社内LAN、ITネットワーク。
* **Level 3.5 (Industrial DMZ)**: IT網とOT網の緩衝地帯。直接通信を遮断する壁。
* **Level 2 / 1 / 0 (OT Network)**: HMIやPLC、センサーが属する絶対防衛線。

かつてのOT網は、外部と物理的に繋がらない「エアギャップ」で守られていました。しかし、IoT化やリモートメンテナンスの需要（IT/OTコンバージェンス）により、このエアギャップは崩壊しつつあります。

### 【歴史的教訓：ウクライナ電力網サイバー攻撃（2015年）】
割と何回もこの話をしますが、

エアギャップの崩壊と境界管理の甘さが引き起こした最も有名な事件が、2015年のウクライナでの大規模停電です。

攻撃者はIT網（Level 4/5）に侵入後、保守作業員がリモートからOT網にアクセスするためのVPN（踏み台）に対して、窃取した資格情報でログインしました。この境界に「多要素認証（MFA）」が存在しなかったためOT網（Level 2）への侵入を許し、遠隔操作で次々とブレーカーを落とされるという壊滅的な被害をもたらしました。

この悲劇を防ぐための新たな防御壁として必須となったのが **Industrial DMZ（Level 3.5）** と **Jump Server（踏み台サーバー）** です。

![統合型Purdueモデル](https://static.zenn.studio/user-upload/0ac5bf8c58d0-20260721.png)

*(図: 統合型Purdueモデルの階層アーキテクチャ。DMZを境界としてITとOTが分離される)*

---

## 3. なぜ「Hyper-V + WSL2」のハイブリッド構成にするのか？

DMZやJump Serverを作るだけなら、Dockerコンテナ（LinuxのSSHコンテナ等）を並べるだけで簡単に再現可能です。

しかし今回は、あえて **Hyper-V上の「Windows Server Core VM」をJump Serverとし、WSL2上のDockerと直接繋ぐハイブリッド構成** を採用します。

その理由は以下の3つです。

1. **実環境のリアリティ**: 実際のプラントや重要インフラにおいて、Jump Serverが軽量Linuxコンテナであることは稀であり、多くの場合Active Directoryと連携したWindows Serverが稼働しています。
2. **フォレンジック・インシデントレスポンス演習のため**: 攻撃者がJump Serverを侵害するシナリオにおいて、Hyper-VのVMであれば**メモリダンプ（`.raw` や `.vmem`）を採取し、Volatility 3 等を用いた本格的な「メモリフォレンジック解析」**の訓練が可能になります。
3. **L2ネットワークのハッキング体験**: Hyper-Vの仮想スイッチとWSL2のMacvlan/Bridgeを直結させることで、仮想ハイパーバイザを跨いだ生パケットの傍受や中間者攻撃（MITM）の検証環境が手に入ります。

---

## 4. ハイブリッド・アーキテクチャの実装

以下の本格的な構成を構築します。

* **ホストOS (Windows 11)**: Level 4/5 (Enterprise)
* **Hyper-V VM (Windows Server Core)**: Level 3.5 (Industrial DMZ / Jump Server) `192.168.150.10`
* **WSL2 Docker (Node-RED & Rust)**: Level 2/1/0 (OT Network) `192.168.150.20`, `192.168.150.21`

---

※本ラボ環境の Jump Server（DMZ）構築には Hyper-V を使用するため、ホストOSは Windows 11 Pro 以上 の環境を前提としています。（※なお、VMware Workstation や VirtualBox 等の他ハイパーバイザ環境でも同様のネットワーク構成で代用可能です）

---

### Step 1: Hyper-V 仮想スイッチの作成（ホスト側）

```powershell
New-VMSwitch -SwitchName "OT-Lab-Switch" -SwitchType Internal
New-NetIPAddress -InterfaceAlias "vEthernet (OT-Lab-Switch)" -IPAddress 192.168.150.1 -PrefixLength 24
```

![Hyper-V仮想スイッチ作成結果](https://static.zenn.studio/user-upload/6266b88d020b-20260722.png)

---

### Step 2: Windows Server Core の構築と初期設定（ホスト側）

1. **VMの作成**: Hyper-Vマネージャーで第2世代のVMを作成し、仮想ハードディスク（60GBのVHDX）を割り当てます。
2. **OSのインストール**: 評価版ISOをマウントして起動し、「Windows Server 2022 Standard Evaluation (デスクトップ エクスペリエンスなしのServer Core)」を選んでインストールします。
3. **パスワード設定**: 初回起動時にAdministratorのパスワード（`JumpAdmin123!`）を設定します。
4. **固定IPの設定**: ログイン後、`sconfig` を実行し、「8) ネットワークの設定」から固定IP `192.168.150.10`（サブネット `255.255.255.0`）を設定します。

![Windows Server Coreでのネットワーク設定](https://static.zenn.studio/user-upload/23b8e9bd8445-20260722.png)

---

### Step 3: WSL2 Dockerネットワークの構築（L3ルーティング）

#### Docker Compose の設定 (Bridgeモード)

Docker側には `192.168.151.0/24` という一段深いOT網（Level 0〜2）を割り当てます。

```yaml
networks:
  ot_net:
    driver: bridge
    ipam:
      config:
        - subnet: 192.168.151.0/24
```

#### 静的ルーティング（Static Route）の追加

Windowsホスト側で管理者PowerShellを開き、WSL2のIP（例: `172.25.47.54`）を経由してOT網へルーティングする設定を追加します。

```powershell
# ※ WSL2のIPアドレスは wsl hostname -I で確認します
route add 192.168.151.0 MASK 255.255.255.0 172.25.47.54
```

#### ポートプロキシ（Port Proxy）の設定

Windowsホストの管理者PowerShellでポートプロキシを設定し、仮想スイッチ（`192.168.150.1`）に来たアクセスを Docker の `127.0.0.1:1880` へ転送させます。

```powershell
netsh interface portproxy add v4tov4 listenport=1880 listenaddress=192.168.150.1 connectport=1880 connectaddress=127.0.0.1
```

これにより、Windowsホスト自身が「DMZとOT網を繋ぐリバースプロキシ」として機能します。

---

### Step 4: 最終確認（Jump Server経由のアクセス）

```powershell
C:\Windows\System32\OpenSSH\ssh.exe -L 8880:192.168.150.1:1880 Administrator@192.168.150.10
```

![SSH接続確認](https://static.zenn.studio/user-upload/7e2d8abb6103-20260722.png)

ログイン後、ブラウザで `http://localhost:8880` を開くと、堅牢なDMZの奥深くに配置されたNode-REDの監視盤が表示されます。

```yaml
version: '3.8'

networks:
  ot_macvlan_net:
    external: true

services:
  # 統合監視盤 HMI (Level 2) - 完全隔離
  hmi-nodered:
    image: nodered/node-red:latest
    container_name: hmi-nodered
    volumes:
      - ./hmi_data:/data
    networks:
      ot_macvlan_net:
        ipv4_address: 192.168.150.20
    restart: unless-stopped

  # 仮想センサーエミュレータ (Level 1/0)
  sensor-emulator:
    build:
      context: ./sensor-emulator
      dockerfile: Dockerfile
    container_name: sensor-emulator
    networks:
      ot_macvlan_net:
        ipv4_address: 192.168.150.21
    restart: unless-stopped
```

![Node-REDフロー図](https://static.zenn.studio/user-upload/d64e5dbcb153-20260722.png)

---

## 5. 堅牢化されたOT網への正規アクセス体験

設定完了後、PCのブラウザから直接 `http://localhost:1880/ui` にアクセスしても「接続拒否」されるようになり、OT網の保護が確立されます。

![現状のネットワーク構成図](https://static.zenn.studio/user-upload/24e889bc3b8c-20260722.png)

オペレーターがHMIを視認するためには、一度「Jump Server（Windows Server Core）」にSSH/RDP接続し、そこを踏み台にしてアクセスする必要があります。

```bash
ssh -L 1880:192.168.150.20:1880 Administrator@192.168.150.10
```

このトンネルを開通させて初めて、手元のブラウザでHMI画面を参照できます。これが実際の重要インフラで行われている「DMZを通じたセキュアなリモートアクセス」の実践例です。

---

## 6. おわりに

Purdueモデルに準拠し、IT網とOT網の間に強固なDMZと本格的なJump Serverを構築することができました。

次回以降は、この多層防御環境をベースに「BACnetによる自動門扉制御」や「RTSP監視カメラストリーミング」の統合、および高度な攻撃シナリオ演習へと進んでいきます。
