# Pico USB Sniffer (streaming)

USB Low Speed / Full Speed sniffer chạy trên Raspberry Pi Pico (RP2040). Firmware **stream liên tục** mọi packet lên PC qua USB, kèm tool GUI kiểu Total Phase Data Center: Start/Stop capture, xem live, lưu file khi dừng. Thiết kế cho capture liên tục nhiều giờ (mục tiêu 3 h+).

Phần capture (PIO + giải mã NRZI/bit-stuffing) dựa trên [pico-usb-sniffer-lite](../pico-usb-sniffer-lite) (BSD-3, Alex Taradov & David Reguera Garcia).

```
usb_sniffer/
├── firmware/            Pico SDK 2.3.1 project (VS Code Pico extension compatible)
│   ├── usb_sniffer.c    capture engine + decoder + streaming
│   ├── usb_sniffer.pio  PIO programs (sampler + start sync)
│   ├── protocol.h       binary streaming protocol (device -> PC)
│   ├── usb_descriptors.c, tusb_config.h
│   └── CMakeLists.txt
└── pc_tool/
    ├── usb_sniffer_gui.py   GUI (PySide6)
    ├── capture.py           capture file + analyzer (transfer / transaction / packet)
    ├── usbdecode.py         giải mã request, descriptor, HID report, SCSI/MSC
    ├── sources.py           đọc serial từ Pico + nguồn demo giả lập
    ├── export_pcap.py       xuất file Wireshark .pcapng
    ├── export_usbpcap.py    xuất .pcapng dạng USBPcap (như Wireshark trên Windows)
    ├── export_csv.py        xuất CSV theo định dạng Total Phase Data Center
    ├── protocol.py          protocol + USB helpers
    ├── run_gui.bat          launcher (tạo venv lần đầu)
    ├── app.ico              icon của tool
    ├── build_exe.bat        tạo file .exe / gói zip chạy không cần Python (build_exe.py)
    └── tests/test_pipeline.py
```

## 1. Nối dây

| Pico            | USB bus cần sniff     |
|-----------------|-----------------------|
| **GP10** (pin 14) | **D+** (dây xanh lá) |
| **GP11** (pin 15) | **D-** (dây trắng)   |
| GND (pin 13)    | GND (dây đen)         |
| GP12 (pin 16)   | **KHÔNG nối** (tín hiệu nội bộ PIO1 → PIO0) |

- Tap song song (passive) vào D+/D- giữa host và device. Pull-up/pull-down nội của Pico đã được tắt để không ảnh hưởng bus.
- **Dùng cáp USB ngắn ở đoạn có tap.** Pico đọc D+ bằng ngưỡng GPIO chứ không phải bộ thu vi sai, nên cáp dài dễ gây lỗi CRC/PID/STUFF giả (host vẫn ACK). Thực tế: cáp device dài có 0.4% lỗi trên packet host (38% packet device khi bật Schmitt trigger), rút ngắn cáp thì 0 lỗi.
- Dây tap ngắn (nên dưới 10 cm), xoắn D+, D-, GND với nhau. Chỉ nối D+, D-, GND, **không nối VCC 5 V**.
- Thiết bị ở xa thì dùng hub: tap ở đoạn cáp ngắn giữa hub và thiết bị.
- Cấp nguồn cho Pico trước khi nối vào bus. Không cắm hai host vào cùng một board breakout (nối chung 5 V).
- Hỗ trợ **Low Speed (1.5 Mb/s)** và **Full Speed (12 Mb/s)**. Không hỗ trợ High Speed (480 Mb/s) — thiết bị HS sẽ phải chạy ở FS nếu nối qua hub FS.
- LED onboard (GP25) nháy khi đang capture.

> Yêu cầu ghi "PG10/PG11" được hiểu là GPIO **GP10 / GP11** của Pico.

## 2. Build & nạp firmware

Dùng VS Code + Raspberry Pi Pico extension (SDK 2.3.1, toolchain 15_2_Rel1 như project `PiCo_Pi`): mở thư mục `usb_sniffer/firmware`, Compile, rồi Run.

Hoặc dòng lệnh (Git Bash):

```bash
cd usb_sniffer/firmware
export PATH="$HOME/.pico-sdk/toolchain/15_2_Rel1/bin:$HOME/.pico-sdk/cmake/v4.3.4/bin:$HOME/.pico-sdk/ninja/v1.13.2:$PATH"
export PICO_SDK_PATH="$HOME/.pico-sdk/sdk/2.3.1"
cmake -S . -B build -G Ninja
ninja -C build
~/.pico-sdk/picotool/2.3.1/picotool/picotool.exe load build/usb_sniffer.uf2 -fx
```

Tùy chọn `-DSNIFFER_INPUT_SCHMITT=1` (mặc định `0`) bật lại Schmitt trigger trên chân GP10/GP11 như firmware cũ. Mặc định tắt vì với Schmitt trigger, packet do device gửi bị đọc sai rất nhiều (PID/CRC/STUFF) dù host vẫn ACK. Lúc bắt đầu capture, firmware gửi dòng `Input Schmitt trigger: on/off` để biết file capture dùng bản nào.

Lần nạp đầu: giữ nút BOOTSEL khi cắm Pico, kéo thả `build/usb_sniffer.uf2` vào ổ `RPI-RP2`. Từ đó trở đi firmware có reset interface nên `picotool load -fx` (và menu *Device → Reboot to BOOTSEL* trong tool) tự đưa Pico về BOOTSEL, không cần bấm nút.

## 3. Tool PC

```bat
cd usb_sniffer\pc_tool
run_gui.bat                  :: mở app (lần đầu tự tạo .venv và cài PySide6 + pyserial)
run_gui.bat --demo           :: chạy với dữ liệu giả lập, không cần phần cứng
run_gui.bat file.pusb        :: mở thẳng một file capture
run_gui.bat --console ...    :: giữ cửa sổ console để xem lỗi Python
```

(hoặc `pip install -r requirements.txt` rồi `python usb_sniffer_gui.py`)

Có thể double-click `run_gui.bat` trong Explorer. App mở không kèm cửa sổ console, và lỗi bất ngờ (nếu có) sẽ hiện thành hộp thoại và được ghi vào `pc_tool\error.log`. Để double-click file `.pusb` là mở luôn, chuột phải file `.pusb` → *Open with* → *Choose another app* → chọn `run_gui.bat` → tick *Always*.

Cách dùng:

1. **Port**: chọn cổng COM có tag `[Pico]` (VID 2E8A). `DEMO` = nguồn dữ liệu giả lập.
2. **Speed**: `Auto detect` (đọc trạng thái idle J của D+/D-) hoặc chọn cứng Full/Low.
3. **Fold SOF** / **Fold IN-NAK**: firmware gộp traffic idle (SOF mỗi 1 ms, polling IN→NAK của endpoint interrupt/bulk) thành 1 dòng tóm tắt, ví dụ `[100 SOF] [87 IN-NAK]`. Nên bật khi capture dài vì nó giảm băng thông và dung lượng file hàng chục lần. Packet lỗi và mọi transaction có data vẫn được giữ đầy đủ. IN-NAK của **endpoint 0** không bao giờ bị gộp, để tool hiện được `[N POLL]` bên trong control transfer.
4. **Start**: bắt đầu stream. Bảng cập nhật live và tự cuộn (Autoscroll). Cột như Data Center: `Sp, Index, m:s.ms.us, Dur, Len, Err, Dev, Ep, Record, Summary` (`Index` = số thứ tự packet toàn cục).
5. **Cây phân cấp giống Data Center**. Click mũi tên, double-click hoặc Enter để mở/đóng; `→`/`←` mở/đóng (`←` trên dòng con nhảy về dòng cha); `*` mở mọi cấp.
   - **Transfer**:
     - Control transfer có tên theo request (`Get String Descriptor`, `Set Address`, `Set Configuration`, `Get Max LUN`, `Set Idle`...). Summary hiện kết quả đã giải mã, ví dụ `Index=2 Length=255 "USB Keyboard"`, `VID=… PID=…`, `Configuration=1`, `Max LUN = 0`.
     - Lệnh Mass Storage (CBW → data → CSW) có tên lệnh SCSI và trạng thái, ví dụ `Inquiry [0]` (`Passed`), `Request Sense [0]` (`Sense Key = Unit Attention`), `Read(10) [0]` (`LBA=… Blocks=…`).
     - Nhóm SOF (`[N SOF]`).
   - **Transaction**: `SETUP txn`, `IN txn`, `OUT txn`, `IN txn [28 POLL]`. Các lần bị NAK được gộp vào lần thành công sau đó (POLL). Một lần thử đơn lẻ bị NAK hiện là `[NAK]`, còn `[STALL]` báo endpoint bị stall.
   - **Packet**: `SETUP/IN/OUT packet`, `DATA0/DATA1 packet`, `ACK/NAK/STALL packet`, `SOF packet`. Summary là byte thô từ PID tới CRC, Len là độ dài packet (giống Data Center).
6. Tab **Details**:
   - Setup packet: bmRequestType, bRequest, wValue, wIndex, wLength.
   - Descriptor: Device, Configuration (gồm Interface, Endpoint, HID, IAD, CDC), String, BOS, HID Report Descriptor (Usage Page, Usage, Collection...).
   - Mass Storage: CBW/CSW, dữ liệu SCSI (Inquiry, Read Capacity, Request Sense).
   - Khung **Data** (dưới, bên phải): hex dump 8 byte/dòng của packet (PID..CRC), payload của transaction, hoặc toàn bộ data stage của transfer.
   - Khung **Statistics** (bên phải): số packet theo loại, control transfer, lỗi; cho cả bus và từng device (tính cả SOF/IN-NAK đã fold).
   - Khung **Navigator** (bên phải): danh sách thiết bị tự học từ enumeration (VID/PID, chuỗi Manufacturer/Product/Serial, toàn bộ cấu hình).
   - **Find** (Ctrl+F, F3/Shift+F3): tìm text trong Record/Summary.
7. **Stop**: dừng capture, tool hỏi lưu: `.pusb` (định dạng gốc, mở lại được bằng **Open**), `.csv` hoặc `.txt` (export bảng).
8. **Wireshark**: *File → Export Wireshark (.pcapng)...* (hoặc chọn loại `Wireshark (*.pcapng)` trong hộp thoại Save), có 2 định dạng:
   - **USBPcap transfers** (mặc định): giống file Wireshark ghi bằng USBPcap trên Windows (linktype 249). Mỗi transfer là 2 frame submit/complete, dùng được các filter và script đọc `usbhid.data`, `usb.src == "1.14.1"`... Thời gian là lúc transfer chạy trên bus (token đầu và packet cuối), không phải lúc driver gửi/nhận URB. SOF, NAK và packet lỗi không có trong định dạng này.
   - **USB packets**: mọi packet trên dây, kể cả packet lỗi, linktype `USB 2.0 Full/Low Speed` (293/294, filter `usbll`). Cần Wireshark 3.6 trở lên. SOF/IN-NAK bị fold thì không có packet để xuất, muốn đủ hãy bỏ tick Fold trước khi capture.
   - Nếu capture không có enumeration, Wireshark không biết device là HID. Tool có thể thêm descriptor vào đầu file USBPcap: lấy từ file tham chiếu (`.pcapng` USBPcap hoặc `.pusb`) nếu có đúng một device khớp endpoint, không thì dùng HID chung (VID/PID 0000). Các frame thêm vào có comment `Not captured`. Cách chính xác nhất là bấm Start trước khi cắm thiết bị.
9. **Filter**: theo Dev/Ep, ẩn SOF/idle, ẩn NAK, chỉ hiện lỗi. *File → Export* xuất theo filter đang áp dụng. CSV theo định dạng Data Center (`Level,Sp,Index,m:s.ms.us,Dur,Len,Err,Dev,Ep,Record,Summary`), chọn *Visible records* (đúng những dòng đang hiện) hoặc *All levels* (mọi transaction/packet). Data bị cắt ở 24 byte giống Data Center, tick *Full data* để xuất đủ. `Index` trong CSV là số thứ tự record (kể cả record đang thu gọn), khác cột Index trong GUI (số thứ tự packet). `Err` dùng mã Data Center: `0` bit-stuff, `B` SYNC, `C` CRC, `I` PID/sai trình tự, `L` độ dài, `P` lẻ bit, `S` mất/cắt packet, `U` mất kết nối. `Ctrl+C` copy các dòng đang chọn.

Thanh trạng thái hiển thị: thời gian chạy, số dòng, tốc độ nhận (KB/s), số packet, và trạng thái thiết bị: **dropped** (packet mất do buffer tràn), độ đầy ring buffer hiện tại/max, PIO stall, sync error, số lần reconnect.

**Autosave**: mọi dữ liệu được ghi thẳng xuống `pc_tool/captures/capture_YYYYmmdd_HHMMSS.pusb` ngay khi nhận, nên crash hay mất điện thì vẫn còn dữ liệu đến thời điểm đó. "Save" là copy file này ra chỗ khác.

### Tạo file exe

Double-click `build_exe.bat` (cần Python 3.10+, lần đầu cần mạng). Kết quả nằm trong `dist/`: `PicoUsbSniffer_win64_<version>.zip` (thư mục + hướng dẫn + firmware, nên dùng) và `PicoUsbSniffer_<version>.exe` (một file, mở chậm hơn). Tùy chọn: `--mode exe|zip|both`, `--version 1.2.3`, `--out FOLDER`, `--skip-tests`, `--clean`. Tool chạy test trước, rồi chạy thử exe ở chế độ demo, lỗi thì không xuất file.

## 4. Kiến trúc & tối ưu cho stream liên tục 3 h

```
 D+/D- ──► PIO1 (start sync) ──► PIO0 (sample 10x bitrate) ──RX FIFO──► core1
                                                                         │ raw ring 128 KB (lock-free)
                                                                         ▼
 PC ◄── USB CDC (16 KB TX FIFO) ◄── records ◄── fold ◄── decode/CRC ◄── core0
```

Firmware:

- **core1** chạy một vòng lặp riêng, không có interrupt nào: chỉ lấy word từ PIO FIFO, ghi vào ring buffer 128 KB và gắn timestamp cho mỗi EOP. Như vậy PIO FIFO không bao giờ tràn, kể cả khi USB phía PC bị chậm.
- Nếu PC đọc không kịp, ring buffer hấp thụ burst (khoảng 85 ms ở bus FS 100% tải, lâu hơn nhiều với traffic thật). Khi tràn hẳn, firmware **bỏ nguyên packet** (không bao giờ ghi packet bị cắt dở) và gửi record `DROP` kèm số lượng. Capture không bị đứng và không bị lệch đồng bộ.
- **core0** giải mã bằng bảng tra (NRZI + bit-unstuff theo từng byte), nhanh khoảng 4 lần vòng lặp từng bit của bản gốc. Code được test so với thuật toán gốc trên 300.000 mẫu ngẫu nhiên, kết quả khớp từng bit. Sau đó kiểm tra CRC5/CRC16, gộp traffic idle, đóng gói record nhị phân rồi gửi qua TinyUSB CDC (transfer 512 byte, TX FIFO 16 KB). Core0 không bao giờ block chờ USB.
- Timestamp 64-bit µs nên không bị tràn (bộ đếm 32-bit µs sẽ tràn sau 71 phút).
- Toàn bộ code chạy từ RAM (`copy_to_ram`), clk_sys 120 MHz, dùng bộ chia PIO nguyên (8 cho LS, 1 cho FS) nên không có jitter.
- Gửi `STATUS` mỗi 500 ms (heartbeat). Khi PC đóng cổng thì capture tự dừng.

Tool PC:

- Thread đọc serial riêng, bộ đệm nhận của OS 8 MB, đọc theo khối 64 KB. Parser kèm phân tích transfer đạt khoảng 16 MB/s (~700k packet/s), gấp khoảng 16 lần băng thông tối đa của USB FS CDC.
- Bộ nhớ không tăng theo số packet: chỉ cấp trên cùng (transfer, transaction, nhóm SOF) được index, mỗi dòng là một *đoạn của file* cộng khoảng 24 byte metadata. Transaction và packet con được dựng lại lazily từ file khi dòng hiện lên hoặc được mở ra. Bảng dùng mô hình "flat tree" ảo nên mở/đóng nhanh dù có hàng triệu dòng.
- Thứ tự dòng theo thời gian bắt đầu: transfer giữ chỗ ở vị trí SETUP/CBW và chỉ hiện khi đã xong (thường < 1 ms). Transfer không hoàn tất sẽ tự đóng (control 1 s / MSC 3 s không hoạt động) với nhãn `[incomplete]`.
- Có kiểm tra resync: nếu luồng byte bị hỏng, parser tự tìm lại biên record.
- **Auto-reconnect**: nếu Pico mất kết nối, hoặc không có dữ liệu trong 3 s, tool tự mở lại cổng và Start lại. Sự kiện được ghi vào capture, timeline vẫn liên tục.

### Giới hạn cần biết

- Băng thông USB FS CDC thực tế khoảng 0.8–1 MB/s. Khi bus bị chiếm gần 100% liên tục bằng packet data lớn (vd. bulk tốc độ tối đa), dữ liệu sinh ra có thể vượt khả năng gửi. Lúc đó sẽ có `DROP`, hiện màu đỏ ở status bar. Traffic thông thường (HID, CDC, enumeration, MSC vừa phải) không gặp vấn đề, nhất là khi bật Fold.
- Độ phân giải timestamp là 1 µs (timer của RP2040). Cột Dur được tính từ số bit.
- Không giải mã High Speed, split transaction chỉ hiển thị raw.

## 5. Giao thức stream (device → PC)

Mỗi record: `A5 <type> <len16 LE> <payload>`. Chi tiết trong [firmware/protocol.h](firmware/protocol.h) và [pc_tool/protocol.py](pc_tool/protocol.py).

| type | record | payload |
|------|--------|---------|
| 0x01 | INFO | version, clk, ring size, pins, build string |
| 0x02 | START | ts, speed, fold flags, auto, line state |
| 0x03 | STOP | ts, reason |
| 0x10 | PACKET | ts_start(u64 µs), nbits, error flags, bytes (SYNC PID ... CRC) |
| 0x11 | RESET | ts |
| 0x12 | KEEPALIVE | ts (LS EOP) |
| 0x13 | SYNCERR | ts, raw size |
| 0x20 | FOLD | t_first, t_last, SOF count + frame range, keep-alive, IN-NAK per addr/ep |
| 0x30 | STATUS | packets, dropped, ring fill/max, PIO stall, records, sync errors |
| 0x31 | DROP | total, delta |
| 0x40 | TEXT | message |

Lệnh PC → device (ASCII): `I` info, `S<A|F|L><0|1><0|1>` start (speed, fold SOF, fold IN-NAK), `P` stop, `R` reboot BOOTSEL.

File `.pusb` = header 16 byte `PUSBSNF1...` + các record ở trên + record `HOST_EVENT` (0x41) do PC ghi vào (session, start, disconnect/reconnect, stop).

## 6. Test

```bat
cd pc_tool
python tests\test_pipeline.py
```

Test kiểm tra:
- CRC của bộ sinh Python khớp với bảng CRC trong firmware.
- Cây transfer → transaction → packet trên luồng enumeration + HID + Mass Storage giả lập (có và không fold): tên request, chuỗi descriptor, `[28 POLL]`, `[STALL]`, lệnh SCSI, Devices.
- Gộp POLL, thứ tự khi traffic xen kẽ, và việc dòng chỉ hiện khi transfer đã xong.
- Round-trip file ở mọi cấp: dữ liệu live và file mở lại cho kết quả giống nhau.
- Resync khi có byte rác, và đo throughput.
