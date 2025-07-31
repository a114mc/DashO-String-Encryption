package me.iris.ambien.obfuscator.transformers.impl.data.string;

import cn.a114.commonutil.random.ThreadLocalRandomManager;
import me.iris.ambien.obfuscator.Ambien;
import me.iris.ambien.obfuscator.asm.SizeEvaluator;
import me.iris.ambien.obfuscator.builders.MethodBuilder;
import me.iris.ambien.obfuscator.transformers.impl.data.StringEncryptionManager;
import me.iris.ambien.obfuscator.utilities.GOTOASMUtils;
import me.iris.ambien.obfuscator.utilities.MathUtil;
import me.iris.ambien.obfuscator.utilities.kek.myj2c.Myj2cASMUtils;
import me.iris.ambien.obfuscator.utilities.string.StringUtil;
import org.objectweb.asm.Label;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

/**
 * Implements an advanced string encryption transformer using various "DashO"-style obfuscation techniques.
 * This class modifies string constants and invokedynamic string concatenations by replacing them with
 * encrypted versions, and injects corresponding decryption logic into the class.
 * <br>
 * The encryption method and injected decryption routine depend on the configured DashO level.
 *
 * <p>Supported DashO levels (configurable via {@link StringEncryptionManager}):
 * <ul>
 *     <li>{@code dashO_a} - Basic XOR with mask logic</li>
 *     <li>{@code dashO_b} - Shifted XOR with random mask</li>
 *     <li>{@code dashO_c} - Advanced shifting and randomized logic</li>
 *     <li>{@code dashO_d} - High-entropy randomized obfuscation</li>
 *     <li>{@code dashO_e} - Parametrized symmetric encryption</li>
 * </ul>
 *
 * <p>This transformer is part of Ambien's string encryption obfuscation pipeline.
 *
 * @author a114mc
 */
public class DashOStringEncryption implements Opcodes {
    // Methods from StringBuilder
    // Name 'toString' not included due to I don't want to shit a shit class that contains only 1 shit method
    public static String[] dashOMethodNames = new String[]{"insert", "indexOf", "lastIndexOf", "append"};

    /**
     * DashO levels
     */
    private static final short dashO_a = 1, dashO_b = 2, dashO_c = 4, dashO_d = 7, dashO_e = 10;
    /**
     * Basic DashO method descriptor
     */
    private static final String descriptor_1 =
            "(Ljava/lang/String;I)Ljava/lang/String;";    // String int -> String

    /**
     * Level 10 String encryption method descriptor
     */
    private static final String descriptor_10 =
            "(IILjava/lang/String;)Ljava/lang/String;";    // int int String -> String

    /**
     * @see #process(ClassNode)
     */
    private static String descriptor = "";
    private static String methodName = "useless";

    public static void process(ClassNode classNode) {
        switch (StringEncryptionManager.dashO_level.getValue()) {
            case dashO_a:
            case dashO_b:
            case dashO_c:
            case dashO_d:
                descriptor = descriptor_1;
                break;
            case dashO_e:
                descriptor = descriptor_10;
                break;

        }
        pre:
        {
            boolean shit0 = StringEncryptionManager.dashO_name.isEnabled();
            int shit = shit0 ? ThreadLocalRandomManager
                    .theThreadLocalRandom
                    .nextInt(0,
                            dashOMethodNames.length
                    ) : ThreadLocalRandomManager.theThreadLocalRandom
                    .nextInt(2,
                            32);
            methodName = shit0?dashOMethodNames[shit]:
            StringUtil.randomStringByNaming(shit,
                    Ambien.get.theNamingNaming
            );
        }
        boolean shouldRemove = true;

        for (MethodNode method : classNode.methods) {

            // Skip the decrypt method itself and empty methods
            if (method.name.equals(
                    methodName) || method.instructions == null || method.instructions.size() == 0) {
                continue;
            }

            InsnList insns = method.instructions;
            if (SizeEvaluator.willOverflow(method, insns)) {
                continue;
            }

            for (AbstractInsnNode insn : insns.toArray()) { // Use toArray() to avoid concurrent modification
                if (insn instanceof LdcInsnNode) {
                    LdcInsnNode ldc = (LdcInsnNode) insn;
                    if (ldc.cst instanceof String) {
                        // Do not process empty string calls
                        if (((String) ldc.cst).isEmpty()) {
                            continue;
                        }
                        shouldRemove = false;
                        processStringConstant(classNode, method, insns, ldc);
                    }
                } else if (insn instanceof InvokeDynamicInsnNode) {
                    InvokeDynamicInsnNode invokeDynamic = (InvokeDynamicInsnNode) insn;
                    if (isStringConcatFactory(invokeDynamic)) {
                        shouldRemove = !processInvokeDynamic(
                                classNode, method, insns,
                                invokeDynamic
                        );
                    }
                }
            }
        }

        doing:
        {
            injectDecryptMethod(classNode); // Ensure decrypt method exists
        }
        post:
        {
            if (shouldRemove) {
                removeDecryptMethod(classNode);
            }
        }
    }

    private static boolean isStringConcatFactory(InvokeDynamicInsnNode invokeDynamic) {
        return "makeConcatWithConstants".equals(
                invokeDynamic.name) && "java/lang/invoke/StringConcatFactory".equals(
                invokeDynamic.bsm.getOwner());
    }

    private static void processStringConstant(ClassNode classNode, MethodNode method, InsnList insns, LdcInsnNode ldc) {
        String original = (String) ldc.cst;
        processString(classNode, method, insns, ldc, original);
    }

    private static boolean processInvokeDynamic(ClassNode classNode, MethodNode method,
                                                InsnList insns, InvokeDynamicInsnNode invokeDynamic
    ) {
        boolean processed = false;
        for (Object arg : invokeDynamic.bsmArgs) {
            if (arg instanceof String) {
                String original = (String) arg;
                // Do not process empty string calls
                if (((String) arg).isEmpty()) {
                    continue;
                }
                processString(classNode, method, insns, invokeDynamic, original);
                processed = true;
            }
        }
        return processed;
    }

    private static void processString(ClassNode classNode, MethodNode method, InsnList insns, AbstractInsnNode node, String original) {
        int b = MathUtil.randomInt('\u3040', '\u309f');
        int c = MathUtil.randomInt(64, 89);
        String encrypted = autoEncode(b, c, original);

        InsnList newList = new InsnList();
        // Level 10: IILjava/lang/String;
        if (StringEncryptionManager.dashO_level.getValue() == dashO_e) {
            newList.add(Myj2cASMUtils.pushInt(b));
            newList.add(Myj2cASMUtils.pushInt(c));
            newList.add(new LdcInsnNode(encrypted));
        } else {
            // Not level 10:
            // Ljava/lang/String;I
            newList.add(new LdcInsnNode(encrypted));
            newList.add(Myj2cASMUtils.pushInt(b));
        }
        newList.add(new MethodInsnNode(
                INVOKESTATIC, classNode.name, methodName,
                descriptor, false
        ));

        insns.insert(node, newList);
        insns.remove(node);
    }

    private static void removeDecryptMethod(ClassNode classNode) {
        classNode.methods.removeIf(
                method -> method.name.equals(methodName) && method.desc.equals(
                        descriptor));
    }

    /**
     * Detect if the injected method already exists in the classNode.
     * If it did not, inject it.
     *
     * @param classNode the class node to check and inject
     * @see DashOStringEncryption#methodName
     * @see DashOStringEncryption#descriptor
     * @author a114mc
     * @author ASMIfier
     */
    private static void injectDecryptMethod(ClassNode classNode) {
        // 检查解密方法是否已存在，防止重复注入
        for (MethodNode existingMethod : classNode.methods) {
            if (existingMethod.name.equals(methodName) && existingMethod.desc.equals(descriptor)) {
                return; // Method exists
            }
        }

        // 定义方法访问标志和签名
        // 假设 'methodName' 和 'descriptor' 是预先定义的常量或字段
        MethodBuilder methodBuilder = MethodBuilder.builder()
                .name(methodName)
                .access(ACC_PRIVATE | ACC_STATIC)
                .desc(descriptor)
                .build();

        // 如果 GOTOASMUtils 需要，应用 synthetic 和 bridge 标志
        if (GOTOASMUtils.shouldMarkAsSynthetic(methodBuilder.buildNode())) {
            methodBuilder.addAccess(ACC_SYNTHETIC);
        }
        if (GOTOASMUtils.shouldMarkAsBridge(methodBuilder.buildNode())) {
            methodBuilder.addAccess(ACC_BRIDGE);
        }

        MethodNode methodVisitor = methodBuilder.buildNode();


        // --- 方法代码生成开始 ---
        methodVisitor.visitCode();
        switch (StringEncryptionManager.dashO_level.getValue()) {
            case dashO_a: {

                methodVisitor.visitInsn(ICONST_4);
                methodVisitor.visitInsn(DUP);
                methodVisitor.visitInsn(ICONST_1);
                methodVisitor.visitInsn(IADD);
                methodVisitor.visitInsn(ICONST_0);
                methodVisitor.visitVarInsn(ALOAD, 0);
                methodVisitor.visitMethodInsn(
                        INVOKEVIRTUAL, "java/lang/String", "toCharArray", "()[C", false);
                methodVisitor.visitInsn(DUP);
                methodVisitor.visitInsn(ARRAYLENGTH);
                methodVisitor.visitVarInsn(ISTORE, 3);
                methodVisitor.visitVarInsn(ASTORE, 2);
                methodVisitor.visitVarInsn(ISTORE, 5);
                methodVisitor.visitInsn(ISHL);
                methodVisitor.visitInsn(ICONST_1);
                methodVisitor.visitInsn(ISUB);
                methodVisitor.visitIntInsn(BIPUSH, 32);
                methodVisitor.visitInsn(IXOR);
                methodVisitor.visitVarInsn(ISTORE, 4);
                Label label0 = new Label();
                methodVisitor.visitLabel(label0);
                methodVisitor.visitVarInsn(ALOAD, 2);
                methodVisitor.visitVarInsn(ILOAD, 5);
                methodVisitor.visitVarInsn(ILOAD, 3);
                Label label1 = new Label();
                methodVisitor.visitJumpInsn(IF_ICMPEQ, label1);
                methodVisitor.visitVarInsn(ILOAD, 5);
                methodVisitor.visitInsn(DUP2);
                methodVisitor.visitInsn(CALOAD);
                methodVisitor.visitVarInsn(ILOAD, 1);
                methodVisitor.visitVarInsn(ILOAD, 4);
                methodVisitor.visitInsn(IAND);
                methodVisitor.visitInsn(SWAP);
                methodVisitor.visitInsn(IXOR);
                methodVisitor.visitIincInsn(1, 1);
                methodVisitor.visitIincInsn(5, 1);
                methodVisitor.visitInsn(I2C);
                methodVisitor.visitInsn(CASTORE);
                methodVisitor.visitJumpInsn(GOTO, label0);
                methodVisitor.visitLabel(label1);
                methodVisitor.visitInsn(ICONST_0);
                methodVisitor.visitVarInsn(ILOAD, 3);
                methodVisitor.visitMethodInsn(
                        INVOKESTATIC, "java/lang/String", "valueOf", "([CII)Ljava/lang/String;", false);
                methodVisitor.visitMethodInsn(
                        INVOKEVIRTUAL, "java/lang/String", "intern", "()Ljava/lang/String;", false);
                methodVisitor.visitInsn(ARETURN);
            }
            break;
            case dashO_b: {
                methodVisitor.visitInsn(ICONST_2);
                methodVisitor.visitInsn(DUP);
                methodVisitor.visitInsn(IADD);
                methodVisitor.visitInsn(DUP);
                methodVisitor.visitInsn(ICONST_1);
                methodVisitor.visitInsn(SWAP);
                methodVisitor.visitInsn(IADD);
                methodVisitor.visitInsn(ICONST_0);
                methodVisitor.visitVarInsn(ALOAD, 0);
                methodVisitor.visitMethodInsn(
                        INVOKEVIRTUAL, "java/lang/String", "toCharArray", "()[C", false);
                methodVisitor.visitInsn(DUP);
                methodVisitor.visitInsn(ARRAYLENGTH);
                methodVisitor.visitVarInsn(ISTORE, 2);
                methodVisitor.visitVarInsn(ASTORE, 3);
                methodVisitor.visitVarInsn(ISTORE, 5);
                methodVisitor.visitInsn(ISHL);
                methodVisitor.visitIntInsn(BIPUSH, -1);
                methodVisitor.visitInsn(IADD);
                methodVisitor.visitIntInsn(BIPUSH, 32);
                methodVisitor.visitInsn(IXOR);
                methodVisitor.visitVarInsn(ISTORE, 4);
                Label label0 = new Label();
                methodVisitor.visitLabel(label0);
                methodVisitor.visitVarInsn(ALOAD, 3);
                methodVisitor.visitVarInsn(ILOAD, 5);
                methodVisitor.visitVarInsn(ILOAD, 2);
                Label label1 = new Label();
                methodVisitor.visitJumpInsn(IF_ICMPEQ, label1);
                methodVisitor.visitVarInsn(ILOAD, 5);
                methodVisitor.visitInsn(DUP2);
                methodVisitor.visitInsn(CALOAD);
                methodVisitor.visitVarInsn(ILOAD, 1);
                methodVisitor.visitVarInsn(ILOAD, 4);
                methodVisitor.visitInsn(IAND);
                methodVisitor.visitInsn(IXOR);
                methodVisitor.visitIincInsn(1, 1);
                methodVisitor.visitIincInsn(5, 1);
                methodVisitor.visitInsn(I2C);
                methodVisitor.visitInsn(CASTORE);
                methodVisitor.visitJumpInsn(GOTO, label0);
                methodVisitor.visitLabel(label1);
                methodVisitor.visitVarInsn(ILOAD, 5);
                methodVisitor.visitInsn(SWAP);
                methodVisitor.visitInsn(ICONST_0);
                methodVisitor.visitVarInsn(ILOAD, 2);
                methodVisitor.visitMethodInsn(
                        INVOKESTATIC, "java/lang/String", "valueOf", "([CII)Ljava/lang/String;", false);
                methodVisitor.visitMethodInsn(
                        INVOKEVIRTUAL, "java/lang/String", "intern", "()Ljava/lang/String;", false);
                methodVisitor.visitInsn(SWAP);
                methodVisitor.visitInsn(POP);
            }
            break;
            case dashO_c: {
                methodVisitor.visitInsn(ICONST_4);
                methodVisitor.visitInsn(DUP);
                methodVisitor.visitInsn(ICONST_1);
                methodVisitor.visitInsn(SWAP);
                methodVisitor.visitInsn(IADD);
                methodVisitor.visitInsn(ICONST_0);
                methodVisitor.visitVarInsn(ALOAD, 0);
                methodVisitor.visitIincInsn(1, 5);
                methodVisitor.visitMethodInsn(
                        INVOKEVIRTUAL, "java/lang/String", "toCharArray", "()[C", false);
                methodVisitor.visitInsn(DUP);
                methodVisitor.visitInsn(ARRAYLENGTH);
                methodVisitor.visitVarInsn(ISTORE, 5);
                methodVisitor.visitVarInsn(ASTORE, 3);
                methodVisitor.visitVarInsn(ISTORE, 2);
                methodVisitor.visitInsn(ISHL);
                methodVisitor.visitInsn(ICONST_1);
                methodVisitor.visitInsn(ISUB);
                methodVisitor.visitIntInsn(BIPUSH, 32);
                methodVisitor.visitInsn(IXOR);
                methodVisitor.visitVarInsn(ISTORE, 4);
                Label label0 = new Label();
                methodVisitor.visitLabel(label0);
                methodVisitor.visitVarInsn(ALOAD, 3);
                methodVisitor.visitVarInsn(ILOAD, 2);
                methodVisitor.visitVarInsn(ILOAD, 5);
                Label label1 = new Label();
                methodVisitor.visitJumpInsn(IF_ICMPEQ, label1);
                methodVisitor.visitVarInsn(ILOAD, 2);
                methodVisitor.visitInsn(DUP2);
                methodVisitor.visitInsn(CALOAD);
                methodVisitor.visitVarInsn(ILOAD, 1);
                methodVisitor.visitVarInsn(ILOAD, 4);
                methodVisitor.visitInsn(IAND);
                methodVisitor.visitInsn(IXOR);
                methodVisitor.visitIincInsn(1, 7);
                methodVisitor.visitIincInsn(2, 1);
                methodVisitor.visitInsn(I2C);
                methodVisitor.visitInsn(CASTORE);
                methodVisitor.visitJumpInsn(GOTO, label0);
                methodVisitor.visitLabel(label1);
                methodVisitor.visitVarInsn(ILOAD, 2);
                methodVisitor.visitInsn(SWAP);
                methodVisitor.visitInsn(ICONST_0);
                methodVisitor.visitVarInsn(ILOAD, 5);
                methodVisitor.visitMethodInsn(
                        INVOKESTATIC, "java/lang/String", "valueOf", "([CII)Ljava/lang/String;", false);
                methodVisitor.visitMethodInsn(
                        INVOKEVIRTUAL, "java/lang/String", "intern", "()Ljava/lang/String;", false);
                methodVisitor.visitInsn(SWAP);
                methodVisitor.visitInsn(POP);
                methodVisitor.visitInsn(ARETURN);
            }
            break;
            case dashO_d: {
                methodVisitor.visitInsn(ICONST_2);
                methodVisitor.visitInsn(DUP);
                methodVisitor.visitInsn(IADD);
                methodVisitor.visitInsn(DUP);
                methodVisitor.visitInsn(ICONST_1);
                methodVisitor.visitInsn(SWAP);
                methodVisitor.visitInsn(IADD);
                methodVisitor.visitInsn(ICONST_0);
                methodVisitor.visitVarInsn(ALOAD, 0);
                methodVisitor.visitIincInsn(1, 12);
                methodVisitor.visitMethodInsn(
                        INVOKEVIRTUAL, "java/lang/String", "toCharArray", "()[C", false);
                methodVisitor.visitInsn(DUP);
                methodVisitor.visitInsn(ARRAYLENGTH);
                methodVisitor.visitVarInsn(ISTORE, 3);
                methodVisitor.visitVarInsn(ASTORE, 4);
                methodVisitor.visitVarInsn(ISTORE, 5);
                methodVisitor.visitInsn(ISHL);
                methodVisitor.visitInsn(ICONST_M1);
                methodVisitor.visitInsn(IADD);
                methodVisitor.visitIntInsn(BIPUSH, 32);
                methodVisitor.visitInsn(IXOR);
                methodVisitor.visitVarInsn(ISTORE, 2);
                Label label0 = new Label();
                methodVisitor.visitLabel(label0);
                methodVisitor.visitVarInsn(ALOAD, 4);
                methodVisitor.visitVarInsn(ILOAD, 5);
                methodVisitor.visitVarInsn(ILOAD, 3);
                Label label1 = new Label();
                methodVisitor.visitJumpInsn(IF_ICMPEQ, label1);
                methodVisitor.visitVarInsn(ILOAD, 5);
                methodVisitor.visitInsn(DUP2);
                methodVisitor.visitInsn(CALOAD);
                methodVisitor.visitVarInsn(ILOAD, 1);
                methodVisitor.visitVarInsn(ILOAD, 2);
                methodVisitor.visitInsn(IAND);
                methodVisitor.visitInsn(IXOR);
                methodVisitor.visitIincInsn(1, 7);
                methodVisitor.visitIincInsn(5, 1);
                methodVisitor.visitInsn(I2C);
                methodVisitor.visitInsn(CASTORE);
                methodVisitor.visitJumpInsn(GOTO, label0);
                methodVisitor.visitLabel(label1);
                methodVisitor.visitVarInsn(ILOAD, 5);
                methodVisitor.visitInsn(SWAP);
                methodVisitor.visitInsn(ICONST_0);
                methodVisitor.visitVarInsn(ILOAD, 3);
                methodVisitor.visitMethodInsn(
                        INVOKESTATIC, "java/lang/String", "valueOf", "([CII)Ljava/lang/String;", false);
                methodVisitor.visitMethodInsn(
                        INVOKEVIRTUAL, "java/lang/String", "intern", "()Ljava/lang/String;", false);
                methodVisitor.visitInsn(SWAP);
                methodVisitor.visitInsn(POP);
                methodVisitor.visitInsn(ARETURN);
            }
            break;
            case dashO_e: {
                Label label0 = new Label();
                methodVisitor.visitLabel(label0);
                methodVisitor.visitLineNumber(48, label0);
                methodVisitor.visitVarInsn(ALOAD, 2);
                methodVisitor.visitMethodInsn(
                        INVOKEVIRTUAL, "java/lang/String", "toCharArray", "()[C", false);
                methodVisitor.visitVarInsn(ASTORE, 3);
                Label label1 = new Label();
                methodVisitor.visitLabel(label1);
                methodVisitor.visitLineNumber(49, label1);
                methodVisitor.visitInsn(ICONST_0);
                methodVisitor.visitVarInsn(ISTORE, 4);
                Label label2 = new Label();
                methodVisitor.visitLabel(label2);
                methodVisitor.visitFrame(
                        Opcodes.F_NEW,
                        5,
                        new Object[]{
                                Opcodes.INTEGER, Opcodes.INTEGER, "java/lang/String", "[C", Opcodes.INTEGER
                        },
                        0,
                        new Object[]{});
                methodVisitor.visitVarInsn(ILOAD, 4);
                methodVisitor.visitVarInsn(ALOAD, 3);
                methodVisitor.visitInsn(ARRAYLENGTH);
                Label label3 = new Label();
                methodVisitor.visitJumpInsn(IF_ICMPGE, label3);
                Label label4 = new Label();
                methodVisitor.visitLabel(label4);
                methodVisitor.visitLineNumber(50, label4);
                methodVisitor.visitVarInsn(ALOAD, 3);
                methodVisitor.visitVarInsn(ILOAD, 4);
                methodVisitor.visitVarInsn(ALOAD, 3);
                methodVisitor.visitVarInsn(ILOAD, 4);
                methodVisitor.visitInsn(CALOAD);
                methodVisitor.visitVarInsn(ILOAD, 0);
                methodVisitor.visitIntInsn(BIPUSH, 95);
                methodVisitor.visitInsn(IAND);
                methodVisitor.visitInsn(IXOR);
                methodVisitor.visitInsn(I2C);
                methodVisitor.visitInsn(CASTORE);
                Label label5 = new Label();
                methodVisitor.visitLabel(label5);
                methodVisitor.visitLineNumber(51, label5);
                methodVisitor.visitVarInsn(ILOAD, 0);
                methodVisitor.visitVarInsn(ILOAD, 1);
                methodVisitor.visitInsn(IADD);
                methodVisitor.visitVarInsn(ISTORE, 0);
                Label label6 = new Label();
                methodVisitor.visitLabel(label6);
                methodVisitor.visitLineNumber(49, label6);
                methodVisitor.visitIincInsn(4, 1);
                methodVisitor.visitJumpInsn(GOTO, label2);
                methodVisitor.visitLabel(label3);
                methodVisitor.visitLineNumber(53, label3);
                methodVisitor.visitFrame(
                        Opcodes.F_NEW,
                        4,
                        new Object[]{Opcodes.INTEGER, Opcodes.INTEGER, "java/lang/String", "[C"},
                        0,
                        new Object[]{});
                methodVisitor.visitTypeInsn(NEW, "java/lang/String");
                methodVisitor.visitInsn(DUP);
                methodVisitor.visitVarInsn(ALOAD, 3);
                methodVisitor.visitMethodInsn(INVOKESPECIAL, "java/lang/String", "<init>", "([C)V", false);
                methodVisitor.visitInsn(ARETURN);
            }
            break;
        }
        // 设置操作数栈和局部变量表的最大大小。
        // 使用 ClassWriter.COMPUTE_MAXS 会自动计算，更方便。
        methodVisitor.visitMaxs(0, 0); // 让 ASM 自动计算最大栈和局部变量数
        methodVisitor.visitEnd();
        // 将新创建的方法添加到类节点中
        classNode.methods.add(methodVisitor);
    }

    // https://github.com/GenericException/SkidSuite
    // Skidded from dashO samples

    /**
     * 对称加解密方法：输入相同参数 n 和 n2，可以加密和解密。
     *
     * @param var1 default key
     * @param n2   step-in key
     * @param var0 input content(encoded or decoded)
     * @return encoded/decoded content
     */
    public static String autoEncode(int var1, int n2, String var0) {
        switch (StringEncryptionManager.dashO_level.getValue()) {
            case dashO_a: {
                int var10001 = 4 + 1;
                char[] var10003 = var0.toCharArray();
                int var3 = var10003.length;
                char[] var2 = var10003;
                int var5 = 0;

                int var10002;
                for (int var4 = (4 << var10001) - 1 ^ 32; var5 != var3; var2[var10001] = (char) var10002) {
                    var10001 = var5;
                    var10002 = var1 & var4 ^ var2[var5];
                    ++var1;
                    ++var5;
                }

                return String.valueOf(var2, 0, var3).intern();

            }
            case dashO_b: {
                int var10000 = 2 + 2;
                int var10001 = 1 + 2 + 2;
                char[] var10003 = var0.toCharArray();
                int var2 = var10003.length;
                char[] var3 = var10003;
                int var5 = 0;

                int var10002;
                for (int var4 = (var10000 << var10001) + -1 ^ 32; var5 != var2; var3[var10001] = (char) var10002) {
                    var10001 = var5;
                    var10002 = var3[var5] ^ var1 & var4;
                    ++var1;
                    ++var5;
                }

                return String.valueOf(var3, 0, var2).intern();


            }
            case dashO_c: {
                int var10001 = 1 + 4;
                var1 += 5;
                char[] var10003 = var0.toCharArray();
                int var5 = var10003.length;
                char[] var3 = var10003;
                int var2 = 0;

                int var10002;
                for (int var4 = (4 << var10001) - 1 ^ 32; var2 != var5; var3[var10001] = (char) var10002) {
                    var10001 = var2;
                    var10002 = var3[var2] ^ var1 & var4;
                    var1 += 7;
                    ++var2;
                }

                return String.valueOf(var3, 0, var5).intern();


            }
            case dashO_d: {
                int var10000 = 2 + 2;
                int var10001 = 1 + 2 + 2;
                var1 += 12;
                char[] var10003 = var0.toCharArray();
                int var3 = var10003.length;
                char[] var4 = var10003;
                int var5 = 0;

                int var10002;
                for (int var2 = (var10000 << var10001) + -1 ^ 32; var5 != var3; var4[var10001] = (char) var10002) {
                    var10001 = var5;
                    var10002 = var4[var5] ^ var1 & var2;
                    var1 += 7;
                    ++var5;
                }

                return String.valueOf(var4, 0, var3).intern();


            }
            case dashO_e: {
                char[] chars = var0.toCharArray();
                for (int i = 0; i < chars.length; i++) {
                    chars[i] = (char) (chars[i] ^ (var1 & 95)); // 95 似乎是硬编码的掩码
                    var1 += n2;
                }
                return new String(chars).intern();
            }
            default:
                throw new RuntimeException("Unexpected value??!!");
        }
    }
}
