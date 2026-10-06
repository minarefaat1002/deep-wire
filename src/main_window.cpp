#include "main_window.hpp"
#include "capture_engine.hpp"
#include "packet_details.hpp"
#include "packet_table_model.hpp"

#include <QComboBox>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QItemSelectionModel>
#include <QLabel>
#include <QPushButton>
#include <QSpinBox>
#include <QSplitter>
#include <QStatusBar>
#include <QTableView>
#include <QTimer>
#include <QVBoxLayout>

#include <exception>
#include <utility>

namespace deep_wire {

MainWindow::MainWindow(QWidget* parent) : QMainWindow{parent}
{
    setWindowTitle("Deep Wire");
    resize(1280, 800);
    auto* central = new QWidget{this};
    auto* layout = new QVBoxLayout{central};
    auto* controls = new QHBoxLayout;
    interfaces_ = new QComboBox{central};
    interfaces_->setObjectName("captureInterface");
    interfaces_->setMinimumWidth(180);
    refresh_ = new QPushButton{"Refresh", central};
    refresh_->setObjectName("refreshInterfaces");
    packet_limit_ = new QSpinBox{central};
    packet_limit_->setObjectName("packetLimit");
    packet_limit_->setRange(1, 1000000);
    packet_limit_->setValue(100000);
    packet_limit_->setGroupSeparatorShown(true);
    start_ = new QPushButton{"Start", central};
    start_->setObjectName("startCapture");
    start_->setToolTip("Start a new capture; replaces the previous packet list");
    stop_ = new QPushButton{"Stop", central};
    stop_->setObjectName("stopCapture");
    stop_->setEnabled(false);
    controls->addWidget(new QLabel{"Interface:", central});
    controls->addWidget(interfaces_);
    controls->addWidget(refresh_);
    controls->addSpacing(16);
    controls->addWidget(new QLabel{"Packet limit:", central});
    controls->addWidget(packet_limit_);
    controls->addWidget(start_);
    controls->addWidget(stop_);
    controls->addStretch();
    layout->addLayout(controls);

    auto* splitter = new QSplitter{Qt::Vertical, central};
    table_ = new QTableView{splitter};
    table_->setObjectName("packetTable");
    packets_ = new PacketTableModel{this};
    table_->setModel(packets_);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setAlternatingRowColors(true);
    table_->setWordWrap(false);
    table_->verticalHeader()->hide();
    table_->verticalHeader()->setDefaultSectionSize(24);
    // Fixed initial widths avoid measuring every stored row during capture.
    table_->setColumnWidth(0, 70);
    table_->setColumnWidth(1, 305);
    table_->setColumnWidth(2, 175);
    table_->setColumnWidth(3, 175);
    table_->setColumnWidth(4, 85);
    table_->setColumnWidth(5, 75);
    table_->horizontalHeader()->setStretchLastSection(true);
    details_ = new PacketDetails{splitter};
    splitter->setSizes({400, 350});
    layout->addWidget(splitter);
    setCentralWidget(central);
    status_ = new QLabel{"Ready", this};
    status_->setObjectName("captureStatus");
    status_->setWordWrap(true);
    count_ = new QLabel{"0 packets | Kernel drops: —", this};
    count_->setObjectName("packetCount");
    count_->setToolTip("Kernel drops count losses at this capture socket only, excluding "
        "NIC and network losses. Loss is dropped / total socket packets, including "
        "dropped and buffered packets.");
    statusBar()->addWidget(status_, 1);
    statusBar()->addPermanentWidget(count_);

    connect(start_, &QPushButton::clicked, this, [this] { start_capture(); });
    connect(stop_, &QPushButton::clicked, this, [this] { stop_capture(); });
    connect(refresh_, &QPushButton::clicked, this, [this] { refresh_interfaces(); });
    connect(table_->selectionModel(), &QItemSelectionModel::currentRowChanged,
        this, [this](const QModelIndex& current, const QModelIndex&) {
            if (const auto* packet = packets_->packet_at(current.row())) {
                details_->show_packet(*packet);
            } else {
                details_->clear();
            }
        });
    update_timer_ = new QTimer{this};
    update_timer_->setInterval(50);
    connect(update_timer_, &QTimer::timeout, this, [this] { receive_update(); });
    refresh_interfaces();
}

MainWindow::~MainWindow()
{
    // CaptureSession joins on destruction; its receive timeout bounds the
    // wait when no packets arrive. The worker never owns widget references.
    session_.request_stop();
}

void MainWindow::refresh_interfaces()
{
    const auto previous = interfaces_->currentText();
    interfaces_->clear();
    try {
        for (const auto& interface : CaptureEngine::list_interfaces()) {
            interfaces_->addItem(QString::fromStdString(interface.name));
        }
        const auto previous_index = interfaces_->findText(previous);
        if (previous_index >= 0) interfaces_->setCurrentIndex(previous_index);
        start_->setEnabled(interfaces_->count() > 0);
        status_->setText(interfaces_->count() > 0 ? "Ready" : "No network interfaces found");
    } catch (const std::exception& error) {
        start_->setEnabled(false);
        status_->setText(QString::fromStdString(error.what()));
    }
}

void MainWindow::set_capturing(const bool capturing)
{
    interfaces_->setEnabled(!capturing);
    refresh_->setEnabled(!capturing);
    packet_limit_->setEnabled(!capturing);
    start_->setEnabled(!capturing && interfaces_->count() > 0);
    stop_->setEnabled(capturing);
}

void MainWindow::start_capture()
{
    try {
        capture_limit_ = packet_limit_->value();
        session_.start(interfaces_->currentText().toStdString(),
            static_cast<std::uint64_t>(capture_limit_));
        packets_->clear();
        details_->clear();
        count_->setText("0 packets | Kernel drops: —");
        stop_requested_ = false;
        set_capturing(true);
        status_->setText("Capturing on " + interfaces_->currentText());
        update_timer_->start();
    } catch (const std::exception& error) {
        status_->setText(QString::fromStdString(error.what()));
        set_capturing(false);
    }
}

void MainWindow::stop_capture()
{
    stop_requested_ = true;
    session_.request_stop();
    stop_->setEnabled(false);
    status_->setText("Stopping capture…");
}

void MainWindow::receive_update()
{
    auto update = session_.take_update();
    packets_->append(std::move(update.packets));
    const auto count = packets_->rowCount();
    QString count_text = QString("%1 packets").arg(count);
    if (update.statistics) {
        const auto& statistics = *update.statistics;
        const double loss = statistics.packets == 0U ? 0.0
            : 100.0 * static_cast<double>(statistics.dropped)
                / static_cast<double>(statistics.packets);
        count_text += QString(" | Kernel drops: %1 (%2%)")
            .arg(static_cast<qulonglong>(statistics.dropped)).arg(loss, 0, 'f', 2);
    } else {
        count_text += update.finished || update.statistics_unavailable
            ? " | Kernel drops: unavailable" : " | Kernel drops: —";
    }
    count_->setText(count_text);
    if (update.finished) {
        update_timer_->stop();
        set_capturing(false);
        if (!update.error.empty()) {
            status_->setText(QString::fromStdString(update.error));
        } else if (!stop_requested_ && count >= capture_limit_) {
            status_->setText("Packet limit reached");
        } else {
            status_->setText("Capture stopped");
        }
    }
}

} // namespace deep_wire
