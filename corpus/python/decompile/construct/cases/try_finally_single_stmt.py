def close(self):
    try:
        self.writer.close()
    finally:
        self.reader.close()
