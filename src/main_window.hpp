#pragma once

#include "capture_session.hpp"

#include <QMainWindow>

class QComboBox;
class QLabel;
class QPushButton;
class QSpinBox;
class QTableView;
class QTimer;

namespace deep_wire {

class PacketDetails;
class PacketTableModel;

class MainWindow : public QMainWindow {
public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override;

private:
    void refresh_interfaces();
    void start_capture();
    void stop_capture();
    void receive_update();
    void set_capturing(bool capturing);

    CaptureSession session_;
    PacketTableModel* packets_{};
    PacketDetails* details_{};
    QComboBox* interfaces_{};
    QSpinBox* packet_limit_{};
    QPushButton* start_{};
    QPushButton* stop_{};
    QPushButton* refresh_{};
    QTableView* table_{};
    QLabel* status_{};
    QLabel* count_{};
    QTimer* update_timer_{};
    bool stop_requested_{};
    int capture_limit_{};
};

} // namespace deep_wire
