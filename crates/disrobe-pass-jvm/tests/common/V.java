import java.io.*;
import java.lang.classfile.*;
import java.lang.classfile.instruction.*;
import java.lang.constant.*;
import java.lang.reflect.*;
import java.util.*;
import java.util.zip.*;

public class V {
    static class L extends ClassLoader {
        Map<String,byte[]> pool;
        Set<String> stubbed = new HashSet<>();
        boolean stubMissing;
        L(Map<String,byte[]> p, boolean stub){ super(V.class.getClassLoader()); pool = p; stubMissing = stub; }
        protected Class<?> findClass(String name) throws ClassNotFoundException {
            byte[] b = pool.get(name);
            if (b != null) return defineClass(name, b, 0, b.length);
            try { return super.findClass(name); }
            catch (ClassNotFoundException e) {
                if (!stubMissing) throw e;
                return defineStub(name);
            }
        }
        Class<?> defineStub(String name) {
            stubbed.add(name);
            ClassDesc cd = ClassDesc.of(name);
            byte[] b = ClassFile.of().build(cd, cb -> cb
                .withFlags(ClassFile.ACC_PUBLIC)
                .withSuperclass(ClassDesc.of("java.lang.RuntimeException")));
            return defineClass(name, b, 0, b.length);
        }
        boolean isStubbed(String name) { return stubbed.contains(name); }
        Class<?> resolveTop(String name) throws ClassNotFoundException {
            Class<?> already = findLoadedClass(name);
            if (already != null) return already;
            return findClass(name);
        }
        Class<?> defineRaw(String name, byte[] b) {
            return defineClass(name, b, 0, b.length);
        }
        void link(Class<?> c){ resolveClass(c); }
    }
    static boolean refsStub(L l, ClassModel cm, MethodModel mm) {
        for (java.lang.classfile.constantpool.PoolEntry pe : cm.constantPool()) {
            String nm = null;
            if (pe instanceof java.lang.classfile.constantpool.ClassEntry ce) {
                nm = ce.asInternalName().replace('/', '.');
                if (nm.startsWith("[")) continue;
            }
            if (nm != null && l.isStubbed(nm)) return true;
        }
        return false;
    }
    static boolean isStub(CodeModel code) {
        int n = 0; boolean athrow = false;
        for (CodeElement ce : code) {
            if (ce instanceof Instruction) {
                n++;
                if (ce instanceof ThrowInstruction) athrow = true;
            }
        }
        return n <= 4 && athrow;
    }
    static int methodsWithCode(byte[] b) {
        ClassModel cm = ClassFile.of().parse(b);
        int n = 0;
        for (MethodModel m : cm.methods())
            if (m.code().isPresent()) n++;
        return n;
    }
    static boolean usesInvokeSpecial(MethodModel mm) {
        for (CodeElement ce : mm.code().get()) {
            if (ce instanceof InvokeInstruction ii && ii.opcode() == Opcode.INVOKESPECIAL) return true;
        }
        return false;
    }
    static int carrierSeq = 0;
    static byte[] carrier(ClassModel cm, MethodModel mm) {
        boolean isStatic = (mm.flags().flagsMask() & ClassFile.ACC_STATIC) != 0;
        String mname = mm.methodName().stringValue();
        MethodTypeDesc origType = mm.methodTypeSymbol();
        MethodTypeDesc carriedType = origType;
        if (!isStatic) {
            ClassDesc recv = cm.thisClass().asSymbol();
            List<ClassDesc> ps = new ArrayList<>();
            ps.add(recv);
            ps.addAll(origType.parameterList());
            carriedType = MethodTypeDesc.of(origType.returnType(), ps);
        }
        final MethodTypeDesc ct = carriedType;
        ClassDesc carrierName = ClassDesc.of("probe.P" + (carrierSeq++));
        return ClassFile.of().build(carrierName, cb -> {
            cb.withFlags(ClassFile.ACC_PUBLIC);
            cb.withSuperclass(ConstantDescs.CD_Object);
            cb.withMethod(mname, ct, ClassFile.ACC_PUBLIC | ClassFile.ACC_STATIC, mb -> {
                mm.code().ifPresent(code -> mb.withCode(xb -> {
                    for (CodeElement ce : code) xb.with(ce);
                }));
            });
        });
    }
    static Map<String,byte[]> readJar(String path) throws IOException {
        Map<String,byte[]> pool = new HashMap<>();
        try (ZipInputStream z = new ZipInputStream(new FileInputStream(path))) {
            ZipEntry e;
            while ((e = z.getNextEntry()) != null) {
                if (!e.getName().endsWith(".class")) continue;
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                byte[] buf = new byte[8192]; int n;
                while ((n = z.read(buf)) > 0) bos.write(buf, 0, n);
                String cn = e.getName().substring(0, e.getName().length()-6).replace('/', '.');
                pool.put(cn, bos.toByteArray());
            }
        }
        return pool;
    }
    static boolean sampled(String key, int permille) {
        if (permille >= 1000) return true;
        return ((key.hashCode() & 0x7fffffff) % 1000) < permille;
    }
    static void runClasses(String jar, int permille) throws Exception {
        Map<String,byte[]> pool = readJar(jar);
        L l = new L(pool, true);
        int verifyClean=0, lifterFail=0, linkSkipped=0, linkUnstable=0;
        int methodsClean=0, methodsLifterFail=0;
        int bodyClean=0, bodyFail=0;
        List<String> errs = new ArrayList<>();
        List<String> bodyErrs = new ArrayList<>();
        List<String> verdicts = new ArrayList<>();
        List<String> names = new ArrayList<>(pool.keySet());
        Collections.sort(names);
        for (String cn : names) {
            int mc = methodsWithCode(pool.get(cn));
            try {
                Class<?> c = l.resolveTop(cn);
                l.link(c);
                c.getDeclaredMethods();
                c.getDeclaredConstructors();
                verifyClean++; methodsClean += mc;
                verdicts.add("CLASSVERDICT CLEAN "+cn);
            } catch (VerifyError ve) {
                String m = String.valueOf(ve.getMessage());
                lifterFail++; methodsLifterFail += mc;
                errs.add("VERIFY "+cn+": "+m.replace('\n',' ').substring(0, Math.min(200, m.length())));
                verdicts.add("CLASSVERDICT REJECT "+cn);
            } catch (VirtualMachineError vme) {
                linkUnstable++;
                verdicts.add("CLASSVERDICT UNSTABLE "+cn);
            } catch (Throwable t) {
                linkSkipped++;
                verdicts.add("CLASSVERDICT SKIP "+cn+" "+t.getClass().getName());
            }
        }
        for (String cn : names) {
            ClassModel cm = ClassFile.of().parse(pool.get(cn));
            for (MethodModel mm : cm.methods()) {
                if (mm.code().isEmpty()) continue;
                if (!sampled(cn+"#"+mm.methodName().stringValue()+mm.methodType().stringValue(), permille)) continue;
                if (mm.methodName().stringValue().equals("<init>")) continue;
                if (mm.methodName().stringValue().equals("<clinit>")) continue;
                if (isStub(mm.code().get())) continue;
                if (usesInvokeSpecial(mm)) continue;
                if (refsStub(l, cm, mm)) continue;
                try {
                    byte[] cb = carrier(cm, mm);
                    Class<?> pc = l.defineRaw(null, cb);
                    l.link(pc);
                    pc.getDeclaredMethods();
                    bodyClean++;
                } catch (VerifyError ve) {
                    bodyFail++;
                    if (bodyErrs.size() < 60) {
                        String m = String.valueOf(ve.getMessage());
                        bodyErrs.add("BODYVERIFY "+cn+"."+mm.methodName().stringValue()
                            +mm.methodType().stringValue()+": "+m.replace('\n',' ').substring(0, Math.min(140, m.length())));
                    }
                } catch (Throwable t) {
                }
            }
        }
        System.out.println("permille="+permille
            +" verify_clean_classes="+verifyClean+" lifter_verify_fail_classes="+lifterFail
            +" link_skipped_classes="+linkSkipped+" link_unstable_classes="+linkUnstable
            +" methods_clean="+methodsClean+" methods_lifter_fail="+methodsLifterFail
            +" body_clean="+bodyClean+" body_fail="+bodyFail);
        for (String s : errs) System.out.println(s);
        for (String s : bodyErrs) System.out.println(s);
        Collections.sort(verdicts);
        for (String s : verdicts) System.out.println(s);
    }
    static void runBodies(String jar, int permille) throws Exception {
        Map<String,byte[]> pool = readJar(jar);
        L l = new L(pool, false);
        int candidates=0, sampledCount=0, presented=0, bodyClean=0, bodyFail=0;
        int exclCtor=0, exclStubBody=0, exclInvokeSpecial=0, exclUnresolved=0, exclOther=0;
        List<String> attested = new ArrayList<>();
        List<String> bodyErrs = new ArrayList<>();
        List<String> names = new ArrayList<>(pool.keySet());
        Collections.sort(names);
        for (String cn : names) {
            ClassModel cm = ClassFile.of().parse(pool.get(cn));
            for (MethodModel mm : cm.methods()) {
                if (mm.code().isEmpty()) continue;
                String mname = mm.methodName().stringValue();
                if (isStub(mm.code().get())) { exclStubBody++; continue; }
                candidates++;
                String key = cn+"#"+mname+mm.methodType().stringValue();
                if (!sampled(key, permille)) continue;
                sampledCount++;
                if (mname.equals("<init>") || mname.equals("<clinit>")) { exclCtor++; continue; }
                if (usesInvokeSpecial(mm)) { exclInvokeSpecial++; continue; }
                presented++;
                try {
                    byte[] cb = carrier(cm, mm);
                    Class<?> pc = l.defineRaw(null, cb);
                    l.link(pc);
                    pc.getDeclaredMethods();
                    bodyClean++;
                    attested.add("ATTEST "+key);
                } catch (VerifyError ve) {
                    bodyFail++;
                    String m = String.valueOf(ve.getMessage());
                    bodyErrs.add("BODYVERIFY "+key+": "+m.replace('\n',' ').substring(0, Math.min(160, m.length())));
                } catch (LinkageError le) {
                    presented--;
                    exclUnresolved++;
                    bodyErrs.add("BODYREJECT "+key+": "+le.getClass().getName()+" "+String.valueOf(le.getMessage()));
                } catch (Throwable t) {
                    presented--;
                    exclOther++;
                    bodyErrs.add("BODYREJECT "+key+": "+t.getClass().getName()+" "+String.valueOf(t.getMessage()));
                }
            }
        }
        System.out.println("permille="+permille
            +" candidate_bodies="+candidates+" sampled_bodies="+sampledCount
            +" presented="+presented+" body_clean="+bodyClean+" body_fail="+bodyFail
            +" excl_ctor="+exclCtor+" excl_stub_body="+exclStubBody
            +" excl_invokespecial="+exclInvokeSpecial+" excl_unresolved="+exclUnresolved
            +" excl_other="+exclOther);
        Collections.sort(attested);
        Collections.sort(bodyErrs);
        for (String s : attested) System.out.println(s);
        for (String s : bodyErrs) System.out.println(s);
    }
    public static void main(String[] a) throws Exception {
        String mode = a[0];
        if (mode.equals("classes")) {
            runClasses(a[2], Integer.parseInt(a[1]));
        } else if (mode.equals("bodies")) {
            runBodies(a[2], Integer.parseInt(a[1]));
        } else {
            System.err.println("usage: V classes <permille> <jar> | V bodies <permille> <jar>");
            System.exit(2);
        }
    }
}
