"use client";

import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Image as ImageIcon,
  Download,
  ZoomIn,
  X,
  FileImage,
  ExternalLink,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import type { ExtractedImage } from "@/lib/types";
import { mockImages } from "@/lib/mock-data";
import { cn } from "@/lib/utils";

export function ImageGallery() {
  const [selectedImage, setSelectedImage] = useState<ExtractedImage | null>(null);
  const [viewMode, setViewMode] = useState<"grid" | "list">("grid");

  const formatBytes = (bytes: number) => {
    if (bytes >= 1048576) return `${(bytes / 1048576).toFixed(2)} MB`;
    if (bytes >= 1024) return `${(bytes / 1024).toFixed(2)} KB`;
    return `${bytes} B`;
  };

  const totalSize = mockImages.reduce((acc, img) => acc + img.size, 0);

  return (
    <div className="space-y-6">
      {/* Header Stats */}
      <Card className="bg-[#0D1117]/60 backdrop-blur-sm border border-white/5">
        <CardContent className="p-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-6">
              <div className="flex items-center gap-2">
                <FileImage className="w-5 h-5 text-green-400" />
                <span className="text-white font-medium">{mockImages.length} images</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-gray-400">Total size:</span>
                <span className="text-cyan-400 font-mono">{formatBytes(totalSize)}</span>
              </div>
            </div>
            <div className="flex gap-2">
              <Button
                variant={viewMode === "grid" ? "default" : "outline"}
                size="sm"
                onClick={() => setViewMode("grid")}
                className={cn(
                  viewMode === "grid"
                    ? "bg-cyan-600 hover:bg-cyan-500"
                    : "border-white/10"
                )}
              >
                Grid
              </Button>
              <Button
                variant={viewMode === "list" ? "default" : "outline"}
                size="sm"
                onClick={() => setViewMode("list")}
                className={cn(
                  viewMode === "list"
                    ? "bg-cyan-600 hover:bg-cyan-500"
                    : "border-white/10"
                )}
              >
                List
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Image Grid */}
      {viewMode === "grid" && (
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4">
          {mockImages.map((image, index) => (
            <motion.div
              key={image.filename}
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ duration: 0.3, delay: index * 0.05 }}
            >
              <Card
                className="bg-[#0D1117]/60 backdrop-blur-sm border border-white/5 hover:border-cyan-500/30 transition-all cursor-pointer group"
                onClick={() => setSelectedImage(image)}
              >
                <CardContent className="p-2">
                  <div className="aspect-square rounded-lg overflow-hidden bg-[#0A0E1A] mb-2 relative">
                    <img
                      src={image.url}
                      alt={image.filename}
                      className="w-full h-full object-cover transition-transform group-hover:scale-105"
                    />
                    <div className="absolute inset-0 bg-black/50 opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center">
                      <ZoomIn className="w-8 h-8 text-white" />
                    </div>
                  </div>
                  <div className="space-y-1">
                    <p className="text-xs text-white font-mono truncate">{image.filename}</p>
                    <div className="flex items-center justify-between">
                      <Badge variant="secondary" className="text-xs bg-white/5">
                        {image.content_type.split("/")[1].toUpperCase()}
                      </Badge>
                      <span className="text-xs text-gray-500">{formatBytes(image.size)}</span>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </motion.div>
          ))}
        </div>
      )}

      {/* Image List */}
      {viewMode === "list" && (
        <Card className="bg-[#0D1117]/60 backdrop-blur-sm border border-white/5">
          <CardContent className="p-0">
            <div className="divide-y divide-white/5">
              {mockImages.map((image, index) => (
                <motion.div
                  key={image.filename}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ duration: 0.2, delay: index * 0.05 }}
                  className="flex items-center gap-4 p-4 hover:bg-white/5 cursor-pointer transition-colors"
                  onClick={() => setSelectedImage(image)}
                >
                  <div className="w-16 h-16 rounded-lg overflow-hidden bg-[#0A0E1A] flex-shrink-0">
                    <img
                      src={image.url}
                      alt={image.filename}
                      className="w-full h-full object-cover"
                    />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-white font-mono text-sm truncate">{image.filename}</p>
                    <p className="text-xs text-gray-500">
                      Extracted via {image.method} • {formatBytes(image.size)}
                    </p>
                  </div>
                  <Badge variant="secondary" className="bg-white/5">
                    {image.content_type}
                  </Badge>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="text-gray-400 hover:text-white"
                    onClick={(e) => {
                      e.stopPropagation();
                      window.open(image.url, "_blank");
                    }}
                  >
                    <ExternalLink className="w-4 h-4" />
                  </Button>
                </motion.div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Image Detail Dialog */}
      <Dialog open={!!selectedImage} onOpenChange={() => setSelectedImage(null)}>
        <DialogContent className="bg-[#0D1117] border-white/10 text-white max-w-4xl">
          <DialogHeader>
            <DialogTitle className="text-cyan-400 flex items-center gap-2">
              <ImageIcon className="w-5 h-5" />
              {selectedImage?.filename}
            </DialogTitle>
          </DialogHeader>
          {selectedImage && (
            <div className="space-y-4">
              <div className="aspect-video rounded-lg overflow-hidden bg-[#0A0E1A]">
                <img
                  src={selectedImage.url}
                  alt={selectedImage.filename}
                  className="w-full h-full object-contain"
                />
              </div>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="bg-[#0A0E1A] rounded-lg p-3">
                  <p className="text-xs text-gray-500 mb-1">Filename</p>
                  <p className="text-sm font-mono text-white">{selectedImage.filename}</p>
                </div>
                <div className="bg-[#0A0E1A] rounded-lg p-3">
                  <p className="text-xs text-gray-500 mb-1">Size</p>
                  <p className="text-sm font-mono text-white">{formatBytes(selectedImage.size)}</p>
                </div>
                <div className="bg-[#0A0E1A] rounded-lg p-3">
                  <p className="text-xs text-gray-500 mb-1">Content Type</p>
                  <p className="text-sm font-mono text-white">{selectedImage.content_type}</p>
                </div>
                <div className="bg-[#0A0E1A] rounded-lg p-3">
                  <p className="text-xs text-gray-500 mb-1">Extraction Method</p>
                  <p className="text-sm font-mono text-white">{selectedImage.method}</p>
                </div>
              </div>
              <div className="flex justify-end gap-2">
                <Button
                  variant="outline"
                  onClick={() => setSelectedImage(null)}
                  className="border-white/10"
                >
                  <X className="w-4 h-4 mr-2" />
                  Close
                </Button>
                <Button
                  className="bg-cyan-600 hover:bg-cyan-500"
                  onClick={() => {
                    const link = document.createElement("a");
                    link.href = selectedImage.url;
                    link.download = selectedImage.filename;
                    link.click();
                  }}
                >
                  <Download className="w-4 h-4 mr-2" />
                  Download
                </Button>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
