package com.zeroknowledge.model;

import java.awt.Rectangle;
import java.util.Objects;

/**
 * Immutable 2D bounding box representing a region on a specific PDF page
 * in PDF user-space points (1/72 inch), with exact conversion helpers for
 * rendered image pixel coordinates, page rotation, and crop boxes.
 */
public final class PdfBoundingBox {

    private final int pageNumber;
    private final double x;
    private final double y;
    private final double width;
    private final double height;
    private final double pageWidth;
    private final double pageHeight;
    private final int rotation;

    /**
     * Constructs a bounding box in PDF user-space coordinates (origin at bottom-left of page box).
     *
     * @param pageNumber 1-based page number
     * @param x          horizontal offset from left edge in points
     * @param y          vertical offset from bottom edge in points
     * @param width      width in points
     * @param height     height in points
     * @param pageWidth  full page width in points
     * @param pageHeight full page height in points
     * @param rotation   page rotation in degrees (0, 90, 180, 270)
     */
    public PdfBoundingBox(
            int pageNumber,
            double x,
            double y,
            double width,
            double height,
            double pageWidth,
            double pageHeight,
            int rotation) {
        if (pageNumber < 1) {
            throw new IllegalArgumentException("pageNumber must be >= 1, got: " + pageNumber);
        }
        this.pageNumber = pageNumber;
        this.x = x;
        this.y = y;
        this.width = Math.max(0.0, width);
        this.height = Math.max(0.0, height);
        this.pageWidth = pageWidth > 0 ? pageWidth : 612.0;
        this.pageHeight = pageHeight > 0 ? pageHeight : 792.0;
        this.rotation = ((rotation % 360) + 360) % 360;
    }

    public PdfBoundingBox(int pageNumber, double x, double y, double width, double height) {
        this(pageNumber, x, y, width, height, 612.0, 792.0, 0);
    }

    public int getPageNumber() {
        return pageNumber;
    }

    public double getX() {
        return x;
    }

    public double getY() {
        return y;
    }

    public double getWidth() {
        return width;
    }

    public double getHeight() {
        return height;
    }

    public double getPageWidth() {
        return pageWidth;
    }

    public double getPageHeight() {
        return pageHeight;
    }

    public int getRotation() {
        return rotation;
    }

    /**
     * Returns the Y coordinate measured top-down from the top edge of the page in points.
     */
    public double getTopDownY() {
        return Math.max(0.0, pageHeight - (y + height));
    }

    public boolean isValid() {
        return pageNumber >= 1 && width > 0.1 && height > 0.1;
    }

    /**
     * Converts this PDF user-space bounding box into pixel coordinates within an image
     * covering the given placement box on the page (or the full page if placementBox is null).
     *
     * @param imageWidthPx  width of the target raster image in pixels
     * @param imageHeightPx height of the target raster image in pixels
     * @param placementBox  where the image is placed on the PDF page (null for full-page render)
     * @param paddingPx     safety margin in pixels added around all 4 sides
     * @return pixel rectangle clamped to the image dimensions
     */
    public Rectangle toPixelRect(
            int imageWidthPx,
            int imageHeightPx,
            PdfBoundingBox placementBox,
            int paddingPx) {
        double refX = (placementBox != null && placementBox.width > 0) ? placementBox.x : 0.0;
        double refY = (placementBox != null && placementBox.height > 0) ? placementBox.y : 0.0;
        double refW = (placementBox != null && placementBox.width > 0) ? placementBox.width : pageWidth;
        double refH = (placementBox != null && placementBox.height > 0) ? placementBox.height : pageHeight;

        double relLeft = (this.x - refX) / refW;
        double relTop = ((refY + refH) - (this.y + this.height)) / refH;
        double relW = this.width / refW;
        double relH = this.height / refH;

        int px = (int) Math.floor(relLeft * imageWidthPx) - paddingPx;
        int py = (int) Math.floor(relTop * imageHeightPx) - paddingPx;
        int pw = (int) Math.ceil(relW * imageWidthPx) + (paddingPx * 2);
        int ph = (int) Math.ceil(relH * imageHeightPx) + (paddingPx * 2);

        int clampedX = Math.max(0, Math.min(imageWidthPx - 1, px));
        int clampedY = Math.max(0, Math.min(imageHeightPx - 1, py));
        int clampedRight = Math.max(clampedX + 1, Math.min(imageWidthPx, px + pw));
        int clampedBottom = Math.max(clampedY + 1, Math.min(imageHeightPx, py + ph));

        return new Rectangle(clampedX, clampedY, clampedRight - clampedX, clampedBottom - clampedY);
    }

    public Rectangle toPixelRect(int imageWidthPx, int imageHeightPx, int paddingPx) {
        return toPixelRect(imageWidthPx, imageHeightPx, null, paddingPx);
    }

    /**
     * Maps an OCR pixel bounding box (origin at top-left of image) into PDF user-space points
     * (origin at bottom-left of page), accounting for image placement on the page and page rotation.
     */
    public static PdfBoundingBox fromImagePixels(
            int pageNumber,
            int pixelLeft,
            int pixelTop,
            int pixelWidth,
            int pixelHeight,
            int imageWidthPx,
            int imageHeightPx,
            PdfBoundingBox imagePlacementOnPage,
            double fullPageWidthPts,
            double fullPageHeightPts,
            int pageRotation) {
        if (imageWidthPx <= 0 || imageHeightPx <= 0) {
            throw new IllegalArgumentException("Image dimensions must be positive");
        }
        double placeX = (imagePlacementOnPage != null) ? imagePlacementOnPage.x : 0.0;
        double placeY = (imagePlacementOnPage != null) ? imagePlacementOnPage.y : 0.0;
        double placeW = (imagePlacementOnPage != null && imagePlacementOnPage.width > 0)
                ? imagePlacementOnPage.width : fullPageWidthPts;
        double placeH = (imagePlacementOnPage != null && imagePlacementOnPage.height > 0)
                ? imagePlacementOnPage.height : fullPageHeightPts;

        double scaleX = placeW / (double) imageWidthPx;
        double scaleY = placeH / (double) imageHeightPx;

        double boxW = pixelWidth * scaleX;
        double boxH = pixelHeight * scaleY;
        double boxX = placeX + (pixelLeft * scaleX);
        // Flip top-down image Y to bottom-up PDF user-space Y
        double boxY = placeY + placeH - ((pixelTop + pixelHeight) * scaleY);

        return new PdfBoundingBox(
                pageNumber,
                boxX,
                boxY,
                boxW,
                boxH,
                fullPageWidthPts,
                fullPageHeightPts,
                pageRotation);
    }

    /**
     * Returns the smallest bounding box enclosing both {@code this} and {@code other} on the same page.
     */
    public PdfBoundingBox union(PdfBoundingBox other) {
        Objects.requireNonNull(other, "other must not be null");
        if (this.pageNumber != other.pageNumber) {
            throw new IllegalArgumentException("Cannot union bounding boxes from different pages");
        }
        double minX = Math.min(this.x, other.x);
        double minY = Math.min(this.y, other.y);
        double maxX = Math.max(this.x + this.width, other.x + other.width);
        double maxY = Math.max(this.y + this.height, other.y + other.height);
        return new PdfBoundingBox(
                this.pageNumber,
                minX,
                minY,
                maxX - minX,
                maxY - minY,
                this.pageWidth,
                this.pageHeight,
                this.rotation);
    }

    /**
     * Checks whether {@code other} is on the same page and vertical line as {@code this},
     * and close enough horizontally to merge without covering unrelated content.
     */
    public boolean canMergeOnSameLine(PdfBoundingBox other, double maxHorizontalGapPts) {
        if (other == null || this.pageNumber != other.pageNumber) {
            return false;
        }
        double minH = Math.min(this.height, other.height);
        double verticalOverlap = Math.min(this.y + this.height, other.y + other.height)
                - Math.max(this.y, other.y);
        if (verticalOverlap < minH * 0.35 && Math.abs(this.y - other.y) > Math.max(4.0, minH * 0.5)) {
            return false;
        }
        double rightThis = this.x + this.width;
        double rightOther = other.x + other.width;
        double horizontalGap = Math.max(0.0, Math.max(this.x - rightOther, other.x - rightThis));
        return horizontalGap <= maxHorizontalGapPts;
    }

    @Override
    public String toString() {
        return String.format(
                "Page %d [x=%.1f, y=%.1f, w=%.1f, h=%.1f]",
                pageNumber, x, y, width, height);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof PdfBoundingBox that)) return false;
        return pageNumber == that.pageNumber
                && Double.compare(that.x, x) == 0
                && Double.compare(that.y, y) == 0
                && Double.compare(that.width, width) == 0
                && Double.compare(that.height, height) == 0
                && rotation == that.rotation;
    }

    @Override
    public int hashCode() {
        return Objects.hash(pageNumber, x, y, width, height, rotation);
    }
}
