package obfuscator.transform.impl.data;

import a114.commonutil.ASMTools;
import obfuscator.Obfuscator;
import obfuscator.transform.Transformer;
import org.objectweb.asm.tree.*;


/***
 * Source: <a href="https://www.exploit-db.com/docs/english/13132-cracking-string-encryption-in-java-obfuscated-bytecode.pdf">Cracking String Encryption in Java Obfuscated Bytecode</a>
 */
public class DashO320StringEncryption extends Transformer {

    private static final String decryptorDesc = "(Ljava/lang/String;)Ljava/lang/String;";

    public DashO320StringEncryption(Obfuscator.Context context) {
        super(context);
    }

    public static String encrypt(String input) {
        char[] buffer = new char[input.length()];
        input.getChars(0, input.length(), buffer, 0);
        int n = 0;
        for (int i = 0; i < buffer.length; ++i) {
            int n2 = n;
            n = (char)(n + 1);
            buffer[i] = (char)((buffer[i] ^ n2) + 1);
        }
        return new String(buffer);
    }


    @Override
    public void transform() {
        for (ClassNode classNode : context.getJar().getClasses()) {
            boolean any = false;
            String decryptorName = context.getDictionary().nextMethodName(classNode, decryptorDesc);
            for (MethodNode method : classNode.methods) {
                if (blacklisted(classNode, method)) {
                    continue;
                }
                for (AbstractInsnNode insn : method.instructions) {
                    if (insn instanceof LdcInsnNode ldc && ldc.cst instanceof String ldcStr && ldcStr.length() > 2) {
                        InsnList inst = new InsnList();
                        inst.add(new LdcInsnNode(encrypt(ldcStr)));
                        inst.add(new MethodInsnNode(INVOKESTATIC, classNode.name, decryptorName, decryptorDesc));
                        method.instructions.insertBefore(ldc, inst);
                        method.instructions.remove(ldc);
                        any = true;
                    }
                }
            }
            if (any) {
                MethodNode method = new MethodNode(ACC_PRIVATE | ACC_STATIC, decryptorName, decryptorDesc, null, null);
                ASMTools.Instructions inst = ASMTools.Instructions.newBuilder();

                // 为每个行号创建锚点标签
                LabelNode line12Label = new LabelNode();
                LabelNode line13Label = new LabelNode();
                LabelNode line14Label = new LabelNode();
                LabelNode line15Label = new LabelNode();
                LabelNode line16Label = new LabelNode();
                LabelNode line17Label = new LabelNode();
                LabelNode loopStartLabel = new LabelNode();   // 循环开始（条件判断）
                LabelNode loopEndLabel = new LabelNode();

                // line 12: char[] ac = new char[s.length()]
                inst.label(line12Label)
                        .line(12, line12Label)
                        .aload(0)                                 // s
                        .method(INVOKEVIRTUAL, "java/lang/String", "length", "()I")
                        .intInsn(NEWARRAY, T_CHAR)                // new char[s.length()]
                        .astore(1);                               // ac

                // line 13: s.getChars(0, s.length(), ac, 0)
                inst.label(line13Label)
                        .line(13, line13Label)
                        .aload(0)                                 // s
                        .insn(ICONST_0)                           // srcBegin = 0
                        .aload(0)                                 // s
                        .method(INVOKEVIRTUAL, "java/lang/String", "length", "()I")
                        .aload(1)                                 // ac
                        .insn(ICONST_0)                           // dstBegin = 0
                        .method(INVOKEVIRTUAL, "java/lang/String", "getChars", "(II[CI)V");

                // line 14: int c = 0
                inst.label(line14Label)
                        .line(14, line14Label)
                        .insn(ICONST_0)
                        .istore(2);                               // c = 0

                // line 15: int i = 0  (循环初始化)
                inst.label(line15Label)
                        .line(15, line15Label)
                        .insn(ICONST_0)
                        .istore(3);                               // i = 0

                // 循环开始（条件判断仍属于 line 15，但无需重复 line 节点）
                inst.label(loopStartLabel);
                // 检查 i < ac.length
                inst.iload(3)                                 // i
                        .aload(1)                                 // ac
                        .insn(ARRAYLENGTH)                        // ac.length
                        .jump(IF_ICMPGE, loopEndLabel);           // if i >= ac.length goto loopEnd

                // line 16: 循环体
                inst.label(line16Label)
                        .line(16, line16Label)
                        .aload(1)                                 // ac
                        .iload(3)                                 // i
                        .aload(1)                                 // ac
                        .iload(3)                                 // i
                        .insn(CALOAD)                             // ac[i]
                        .insn(ICONST_1)                           // 1
                        .insn(ISUB)                               // ac[i] - 1
                        .iload(2)                                 // c (旧值)
                        .iload(2)                                 // c (旧值，用于异或)
                        .insn(ICONST_1)                           // 1
                        .insn(IADD)                               // c + 1
                        .insn(I2C)                                // (char)(c+1)
                        .istore(2)                                // c = (char)(c+1)
                        .insn(IXOR)                               // (ac[i]-1) ^ 旧c
                        .insn(I2C)                                // 转回char
                        .insn(CASTORE);                           // 存回ac[i]

                // 循环步进 (无单独行号，延续 line 16 或 line 15)
                inst.iinc(3, 1)                               // i++
                        .jump(GOTO, loopStartLabel);              // goto loopStart

                // line 17: 返回新字符串
                inst.label(line17Label)
                        .line(17, line17Label)
                        .label(loopEndLabel)                      // 循环结束标签
                        .type(NEW, "java/lang/String")
                        .insn(DUP)
                        .aload(1)                                 // ac
                        .method(INVOKESPECIAL, "java/lang/String", "<init>", "([C)V")
                        .insn(ARETURN);

                inst.replaceMethodInstructions(method);
                classNode.methods.add(method);
            }
        }
    }
}
