// automatically generated by the FlatBuffers compiler, do not modify

package ee.cyber.cdoc20.fbs.header;

import java.nio.*;
import java.lang.*;
import java.util.*;
import com.google.flatbuffers.*;

@SuppressWarnings("unused")
public final class RecipientRecord extends Table {
  public static void ValidateVersion() { Constants.FLATBUFFERS_2_0_0(); }
  public static RecipientRecord getRootAsRecipientRecord(ByteBuffer _bb) { return getRootAsRecipientRecord(_bb, new RecipientRecord()); }
  public static RecipientRecord getRootAsRecipientRecord(ByteBuffer _bb, RecipientRecord obj) { _bb.order(ByteOrder.LITTLE_ENDIAN); return (obj.__assign(_bb.getInt(_bb.position()) + _bb.position(), _bb)); }
  public void __init(int _i, ByteBuffer _bb) { __reset(_i, _bb); }
  public RecipientRecord __assign(int _i, ByteBuffer _bb) { __init(_i, _bb); return this; }

  public byte detailsType() { int o = __offset(4); return o != 0 ? bb.get(o + bb_pos) : 0; }
  public Table details(Table obj) { int o = __offset(6); return o != 0 ? __union(obj, o + bb_pos) : null; }
  public int encryptedFmk(int j) { int o = __offset(8); return o != 0 ? bb.get(__vector(o) + j * 1) & 0xFF : 0; }
  public int encryptedFmkLength() { int o = __offset(8); return o != 0 ? __vector_len(o) : 0; }
  public ByteVector encryptedFmkVector() { return encryptedFmkVector(new ByteVector()); }
  public ByteVector encryptedFmkVector(ByteVector obj) { int o = __offset(8); return o != 0 ? obj.__assign(__vector(o), bb) : null; }
  public ByteBuffer encryptedFmkAsByteBuffer() { return __vector_as_bytebuffer(8, 1); }
  public ByteBuffer encryptedFmkInByteBuffer(ByteBuffer _bb) { return __vector_in_bytebuffer(_bb, 8, 1); }
  public byte fmkEncryptionMethod() { int o = __offset(10); return o != 0 ? bb.get(o + bb_pos) : 0; }

  public static int createRecipientRecord(FlatBufferBuilder builder,
      byte details_type,
      int detailsOffset,
      int encrypted_fmkOffset,
      byte fmk_encryption_method) {
    builder.startTable(4);
    RecipientRecord.addEncryptedFmk(builder, encrypted_fmkOffset);
    RecipientRecord.addDetails(builder, detailsOffset);
    RecipientRecord.addFmkEncryptionMethod(builder, fmk_encryption_method);
    RecipientRecord.addDetailsType(builder, details_type);
    return RecipientRecord.endRecipientRecord(builder);
  }

  public static void startRecipientRecord(FlatBufferBuilder builder) { builder.startTable(4); }
  public static void addDetailsType(FlatBufferBuilder builder, byte detailsType) { builder.addByte(0, detailsType, 0); }
  public static void addDetails(FlatBufferBuilder builder, int detailsOffset) { builder.addOffset(1, detailsOffset, 0); }
  public static void addEncryptedFmk(FlatBufferBuilder builder, int encryptedFmkOffset) { builder.addOffset(2, encryptedFmkOffset, 0); }
  public static int createEncryptedFmkVector(FlatBufferBuilder builder, byte[] data) { return builder.createByteVector(data); }
  public static int createEncryptedFmkVector(FlatBufferBuilder builder, ByteBuffer data) { return builder.createByteVector(data); }
  public static void startEncryptedFmkVector(FlatBufferBuilder builder, int numElems) { builder.startVector(1, numElems, 1); }
  public static void addFmkEncryptionMethod(FlatBufferBuilder builder, byte fmkEncryptionMethod) { builder.addByte(3, fmkEncryptionMethod, 0); }
  public static int endRecipientRecord(FlatBufferBuilder builder) {
    int o = builder.endTable();
    builder.required(o, 8);  // encrypted_fmk
    return o;
  }

  public static final class Vector extends BaseVector {
    public Vector __assign(int _vector, int _element_size, ByteBuffer _bb) { __reset(_vector, _element_size, _bb); return this; }

    public RecipientRecord get(int j) { return get(new RecipientRecord(), j); }
    public RecipientRecord get(RecipientRecord obj, int j) {  return obj.__assign(__indirect(__element(j), bb), bb); }
  }
}
