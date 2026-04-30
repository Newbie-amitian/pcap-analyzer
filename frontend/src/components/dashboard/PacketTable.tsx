"use client";

import { useState } from "react";
import { motion } from "framer-motion";
import {
  useReactTable,
  getCoreRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  getFilteredRowModel,
  flexRender,
  type ColumnDef,
  type SortingState,
} from "@tanstack/react-table";
import {
  ChevronUp,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  Search,
  Eye,
  X,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import type { Packet } from "@/lib/types";
import { protocolColors } from "@/lib/mock-data";
import { cn } from "@/lib/utils";

interface PacketTableProps {
  packets: Packet[];
}

export function PacketTable({ packets }: PacketTableProps) {
  const [sorting, setSorting] = useState<SortingState>([]);
  const [globalFilter, setGlobalFilter] = useState("");
  const [selectedPacket, setSelectedPacket] = useState<Packet | null>(null);

  const columns: ColumnDef<Packet>[] = [
    {
      accessorKey: "id",
      header: "#",
      cell: ({ row }) => (
        <span className="text-gray-500 text-xs font-mono">{row.original.id}</span>
      ),
      size: 50,
    },
    {
      accessorKey: "timestamp",
      header: "Time",
      cell: ({ row }) => (
        <span className="text-gray-400 text-xs font-mono">
          {new Date(row.original.timestamp * 1000).toLocaleTimeString()}
        </span>
      ),
      size: 100,
    },
    {
      accessorKey: "src_ip",
      header: "Source IP",
      cell: ({ row }) => (
        <span className="text-cyan-400 text-xs font-mono">
          {row.original.src_ip || "N/A"}
        </span>
      ),
      size: 120,
    },
    {
      accessorKey: "src_port",
      header: "Src Port",
      cell: ({ row }) => (
        <span className="text-gray-400 text-xs font-mono">
          {row.original.src_port || "—"}
        </span>
      ),
      size: 80,
    },
    {
      accessorKey: "dst_ip",
      header: "Dest IP",
      cell: ({ row }) => (
        <span className="text-violet-400 text-xs font-mono">
          {row.original.dst_ip || "N/A"}
        </span>
      ),
      size: 120,
    },
    {
      accessorKey: "dst_port",
      header: "Dst Port",
      cell: ({ row }) => (
        <span className="text-gray-400 text-xs font-mono">
          {row.original.dst_port || "—"}
        </span>
      ),
      size: 80,
    },
    {
      accessorKey: "protocol",
      header: "Protocol",
      cell: ({ row }) => {
        const protocol = row.original.protocol;
        const color = protocolColors[protocol] || "#636E72";
        return (
          <Badge
            variant="outline"
            className="text-xs font-mono"
            style={{ borderColor: `${color}40`, color }}
          >
            {protocol}
          </Badge>
        );
      },
      size: 80,
    },
    {
      accessorKey: "length",
      header: "Size",
      cell: ({ row }) => (
        <span className="text-gray-400 text-xs font-mono">
          {row.original.length} B
        </span>
      ),
      size: 70,
    },
    {
      accessorKey: "flags",
      header: "Flags",
      cell: ({ row }) => (
        <span className="text-gray-500 text-xs font-mono">
          {row.original.flags || "—"}
        </span>
      ),
      size: 60,
    },
    {
      id: "actions",
      header: "",
      cell: ({ row }) => (
        <Button
          variant="ghost"
          size="sm"
          className="h-6 w-6 p-0"
          onClick={() => setSelectedPacket(row.original)}
        >
          <Eye className="w-3 h-3 text-gray-500" />
        </Button>
      ),
      size: 40,
    },
  ];

  const table = useReactTable({
    data: packets,
    columns,
    state: {
      sorting,
      globalFilter,
    },
    onSortingChange: setSorting,
    onGlobalFilterChange: setGlobalFilter,
    getCoreRowModel: getCoreRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    initialState: {
      pagination: {
        pageSize: 15,
      },
    },
  });

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3, delay: 0.4 }}
    >
      <Card className="bg-[#0D1117]/60 backdrop-blur-sm border border-white/5">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-white text-lg flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-green-400" />
              Packet Data
            </CardTitle>
            <div className="relative w-64">
              <Search className="absolute left-2 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-500" />
              <Input
                placeholder="Search packets..."
                value={globalFilter}
                onChange={(e) => setGlobalFilter(e.target.value)}
                className="pl-8 bg-[#0A0E1A] border-white/10 text-white text-sm"
              />
              {globalFilter && (
                <Button
                  variant="ghost"
                  size="sm"
                  className="absolute right-1 top-1/2 transform -translate-y-1/2 h-6 w-6 p-0"
                  onClick={() => setGlobalFilter("")}
                >
                  <X className="w-3 h-3" />
                </Button>
              )}
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {/* Table */}
          <div className="rounded-lg border border-white/5 overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-[#0A0E1A]">
                  {table.getHeaderGroups().map((headerGroup) => (
                    <tr key={headerGroup.id}>
                      {headerGroup.headers.map((header) => (
                        <th
                          key={header.id}
                          className="px-3 py-2 text-left text-xs font-medium text-gray-400 uppercase tracking-wider cursor-pointer hover:bg-white/5"
                          style={{ width: header.getSize() }}
                          onClick={header.column.getToggleSortingHandler()}
                        >
                          <div className="flex items-center gap-1">
                            {flexRender(
                              header.column.columnDef.header,
                              header.getContext()
                            )}
                            {header.column.getIsSorted() === "asc" && (
                              <ChevronUp className="w-3 h-3" />
                            )}
                            {header.column.getIsSorted() === "desc" && (
                              <ChevronDown className="w-3 h-3" />
                            )}
                          </div>
                        </th>
                      ))}
                    </tr>
                  ))}
                </thead>
                <tbody className="divide-y divide-white/5">
                  {table.getRowModel().rows.map((row) => (
                    <tr
                      key={row.id}
                      className="hover:bg-white/5 transition-colors"
                    >
                      {row.getVisibleCells().map((cell) => (
                        <td key={cell.id} className="px-3 py-2">
                          {flexRender(
                            cell.column.columnDef.cell,
                            cell.getContext()
                          )}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Pagination */}
          <div className="flex items-center justify-between mt-4">
            <div className="flex items-center gap-2 text-sm text-gray-400">
              <span>
                Page {table.getState().pagination.pageIndex + 1} of{" "}
                {table.getPageCount()}
              </span>
              <span className="text-gray-600">|</span>
              <span>{table.getFilteredRowModel().rows.length} packets</span>
            </div>
            <div className="flex items-center gap-2">
              <Select
                value={table.getState().pagination.pageSize.toString()}
                onValueChange={(value) => table.setPageSize(Number(value))}
              >
                <SelectTrigger className="w-[100px] bg-[#0A0E1A] border-white/10 text-white text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-[#0D1117] border-white/10">
                  {[10, 15, 25, 50].map((size) => (
                    <SelectItem
                      key={size}
                      value={size.toString()}
                      className="text-white text-xs"
                    >
                      {size} rows
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <div className="flex items-center gap-1">
                <Button
                  variant="outline"
                  size="sm"
                  className="h-8 w-8 p-0 border-white/10"
                  onClick={() => table.setPageIndex(0)}
                  disabled={!table.getCanPreviousPage()}
                >
                  <ChevronsLeft className="w-4 h-4" />
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  className="h-8 w-8 p-0 border-white/10"
                  onClick={() => table.previousPage()}
                  disabled={!table.getCanPreviousPage()}
                >
                  <ChevronLeft className="w-4 h-4" />
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  className="h-8 w-8 p-0 border-white/10"
                  onClick={() => table.nextPage()}
                  disabled={!table.getCanNextPage()}
                >
                  <ChevronRight className="w-4 h-4" />
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  className="h-8 w-8 p-0 border-white/10"
                  onClick={() => table.setPageIndex(table.getPageCount() - 1)}
                  disabled={!table.getCanNextPage()}
                >
                  <ChevronsRight className="w-4 h-4" />
                </Button>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Packet Detail Dialog */}
      <Dialog open={!!selectedPacket} onOpenChange={() => setSelectedPacket(null)}>
        <DialogContent className="bg-[#0D1117] border-white/10 text-white max-w-2xl">
          <DialogHeader>
            <DialogTitle className="text-cyan-400 flex items-center gap-2">
              Packet #{selectedPacket?.id}
            </DialogTitle>
          </DialogHeader>
          {selectedPacket && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="bg-[#0A0E1A] rounded-lg p-3">
                  <p className="text-xs text-gray-500 mb-1">Timestamp</p>
                  <p className="text-sm font-mono text-white">
                    {new Date(selectedPacket.timestamp * 1000).toISOString()}
                  </p>
                </div>
                <div className="bg-[#0A0E1A] rounded-lg p-3">
                  <p className="text-xs text-gray-500 mb-1">Protocol</p>
                  <p className="text-sm font-mono text-white">
                    {selectedPacket.protocol}
                  </p>
                </div>
                <div className="bg-[#0A0E1A] rounded-lg p-3">
                  <p className="text-xs text-gray-500 mb-1">Source</p>
                  <p className="text-sm font-mono text-cyan-400">
                    {selectedPacket.src_ip}:{selectedPacket.src_port}
                  </p>
                </div>
                <div className="bg-[#0A0E1A] rounded-lg p-3">
                  <p className="text-xs text-gray-500 mb-1">Destination</p>
                  <p className="text-sm font-mono text-violet-400">
                    {selectedPacket.dst_ip}:{selectedPacket.dst_port}
                  </p>
                </div>
                <div className="bg-[#0A0E1A] rounded-lg p-3">
                  <p className="text-xs text-gray-500 mb-1">Size</p>
                  <p className="text-sm font-mono text-white">
                    {selectedPacket.length} bytes
                  </p>
                </div>
                <div className="bg-[#0A0E1A] rounded-lg p-3">
                  <p className="text-xs text-gray-500 mb-1">TTL</p>
                  <p className="text-sm font-mono text-white">
                    {selectedPacket.ttl || "N/A"}
                  </p>
                </div>
              </div>
              {selectedPacket.payload_preview && (
                <div className="bg-[#0A0E1A] rounded-lg p-3">
                  <p className="text-xs text-gray-500 mb-2">Payload Preview</p>
                  <pre className="text-xs font-mono text-gray-300 whitespace-pre-wrap overflow-x-auto">
                    {selectedPacket.payload_preview}
                  </pre>
                </div>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog>
    </motion.div>
  );
}
