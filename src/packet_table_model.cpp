#include "packet_table_model.hpp"

#include <QDateTime>

#include <algorithm>
#include <chrono>
#include <iterator>
#include <utility>

namespace deep_wire {

QString packet_timestamp(const CapturedFrame& frame)
{
    using namespace std::chrono;
    const auto whole_seconds = floor<seconds>(frame.timestamp);
    const auto fraction = duration_cast<nanoseconds>(frame.timestamp - whole_seconds).count();
    return QDateTime::fromSecsSinceEpoch(whole_seconds.time_since_epoch().count(), Qt::UTC)
        .toString("yyyy-MM-dd HH:mm:ss")
        + QString(".%1 UTC").arg(fraction, 9, 10, QLatin1Char{'0'});
}

PacketTableModel::PacketTableModel(QObject* parent) : QAbstractTableModel{parent} {}

int PacketTableModel::rowCount(const QModelIndex& parent) const
{
    return parent.isValid() ? 0 : static_cast<int>(packets_.size());
}

int PacketTableModel::columnCount(const QModelIndex& parent) const
{
    return parent.isValid() ? 0 : 7;
}

QVariant PacketTableModel::data(const QModelIndex& index, const int role) const
{
    const auto* packet = packet_at(index.row());
    if (!index.isValid() || !packet || index.column() < 0 || index.column() >= 7) return {};
    if (role == Qt::ToolTipRole) {
        if (!packet->error.empty()) return QString::fromStdString(packet->error);
        if (packet->frame.truncated()) return QStringLiteral("Frame was truncated during capture");
        return {};
    }
    if (role == Qt::TextAlignmentRole && (index.column() == 0 || index.column() == 5)) {
        return static_cast<int>(Qt::AlignRight | Qt::AlignVCenter);
    }
    if (role != Qt::DisplayRole) return {};
    switch (index.column()) {
    case 0: return QVariant::fromValue(static_cast<qulonglong>(packet->frame.number));
    case 1: return packet_timestamp(packet->frame);
    case 2: return QString::fromStdString(packet->source);
    case 3: return QString::fromStdString(packet->destination);
    case 4: return QString::fromStdString(packet->protocol);
    case 5: return QVariant::fromValue(static_cast<qulonglong>(packet->frame.original_length));
    default: {
        QString info = QString::fromStdString(packet->info);
        if (packet->frame.truncated()) info += " [truncated]";
        if (!packet->error.empty()) info += " [" + QString::fromStdString(packet->error) + "]";
        return info;
    }
    }
}

QVariant PacketTableModel::headerData(const int section, const Qt::Orientation orientation,
    const int role) const
{
    if (role != Qt::DisplayRole || orientation != Qt::Horizontal) return {};
    static const char* const headers[]{"No.", "Timestamp (UTC)", "Source", "Destination",
        "Protocol", "Length", "Info"};
    if (section < 0 || section >= 7) return {};
    return QString::fromLatin1(headers[section]);
}

void PacketTableModel::append(std::vector<Packet> packets)
{
    if (packets.empty()) return;
    const auto first = static_cast<int>(packets_.size());
    // Allocate before beginInsertRows so an allocation failure cannot leave
    // Qt in the middle of a model notification. Grow geometrically.
    const auto needed = packets_.size() + packets.size();
    if (needed > packets_.capacity()) {
        packets_.reserve(std::max(needed, std::max(std::size_t{256}, packets_.capacity() * 2U)));
    }
    beginInsertRows({}, first, static_cast<int>(needed) - 1);
    packets_.insert(packets_.end(), std::make_move_iterator(packets.begin()),
        std::make_move_iterator(packets.end()));
    endInsertRows();
}

void PacketTableModel::clear()
{
    beginResetModel();
    std::vector<Packet>{}.swap(packets_);
    endResetModel();
}

const Packet* PacketTableModel::packet_at(const int row) const
{
    if (row < 0 || static_cast<std::size_t>(row) >= packets_.size()) return nullptr;
    return &packets_[static_cast<std::size_t>(row)];
}

} // namespace deep_wire
