<?php
/**
 * Created by PhpStorm.
 * User: chuxiaofeng
 * Date: 17/1/9
 * Time: 下午8:00
 */



$f = fopen("swoole_api.php", "w");
Extension::export("swoole", $f);

class Extension
{

    const DOC_TPL_INFO =  <<<'TPL'
/**
 * %s
 *
 * @since %s
 *
 * iniEntries:
%s
 */


TPL;

    const DOC_TPL_CONSTANT =  <<<'TPL'
/**
 * @since %s
 */
define("%s", %s);

TPL;

    const DOC_TPL_FUNCTION = <<<'TPL'
/**
 * 
 * @since %s
 * 
%s
 */
function %s(%s) {}

TPL;

    const DOC_TPL_CLASS = <<<'TPL'
/**
 * %s
 *  
 * @since %s
 * 
 * @package %s
 */
%s
{
%s
}


TPL;

    const DOC_TPL_CLASS_CONSTANT = <<<'TPL'
/**
 * 
 * @since %s
 */
define("%s", %s);


TPL;

    const DOC_TPL_METHOD = <<<TPL
\t/**
\t * %s
\t *  
\t * @since %s
\t * 
%s
\t */
\t%sfunction %s(%s)%s 

TPL;

    const DOC_TPL_NAMESPACE = <<<'TPL'


namespace %s
{
%s
}

TPL;



    /**
     * @param string $extName get_loaded_extensions()
     * @param resource $handle
     */
    public static function export($extName, $handle = STDOUT)
    {
        $ext = new \ReflectionExtension($extName);
        $ver = $ext->getVersion();

        fprintf($handle, "<?php\n\n");

        static::exportInfo($handle, $extName, $ver, $ext->getINIEntries());
        static::exportConstants($handle, $ver, $ext->getConstants());
        static::exportFunctions($handle, $ver, $ext->getFunctions());
        static::exportClasses($handle, $ver, $ext->getClasses());
    }

    private static function exportInfo($handle, $name, $version, array $iniEntries)
    {
        $iniDoc = [];
        foreach ($iniEntries as $iniKey => $iniValue) {
            $iniDoc[] = " * $iniKey = $iniValue";
        }

        fprintf($handle, static::DOC_TPL_INFO, $name, $version, implode(PHP_EOL, $iniDoc));
    }

    private static function exportConstants($handle, $ver, array $constants)
    {
        $buffer = [];
        foreach ($constants as $name => $value) {
            if(!is_numeric($value)) {
                $value ="\"$value\"";
            }
            $buffer[] = static::tabLines(sprintf(static::DOC_TPL_CONSTANT, $ver, $name, $value));
        }

        fprintf($handle, static::DOC_TPL_NAMESPACE, "", implode(PHP_EOL, $buffer));
    }

    /**
     * @param resource $handle
     * @param $ver
     * @param ReflectionFunction[] $functions
     */
    private static function exportFunctions($handle, $ver, array $functions)
    {
        $buffer = [];
        foreach ($functions as $function) {
            // $function->getDocComment();
            // $retType = $function->getReturnType();
            // $function->getShortName();

            if ($function->isVariadic()) {
                $paraStr = "/* ...\$args */";
            } else {
                list($paraStr, $doc) = static::exportParameters($function->getParameters());
            }

            if ($function->isDeprecated()) {
                $doc[] = " * @deprecated";
            }

            $doc[] = " * @return"; // getType

            $shortName = $function->getShortName();
            $oneFunc = sprintf(static::DOC_TPL_FUNCTION, $ver, implode(PHP_EOL, $doc), $shortName, $paraStr);

            $nsName = $function->getNamespaceName();
            if (!isset($buffer[$nsName])) {
                $buffer[$nsName] = [];
            }
            $buffer[$nsName][] = $oneFunc;
        }

        foreach ($buffer as $ns => $funcs) {
            $tabFuncs = [];
            foreach ($funcs as $oneFunc) {
                $tabFuncs[] = static::tabLines($oneFunc);
            }
            fprintf($handle, static::DOC_TPL_NAMESPACE, $ns, implode(PHP_EOL, $tabFuncs));
        }
    }

    /**
     * @param resource $handle
     * @param $ver
     * @param ReflectionClass[] $classes
     */
    private static function exportClasses($handle, $ver, array $classes)
    {
        $buffer = [];

        foreach ($classes as $class) {
            // $class->isAnonymous(); php7

            $modifier = $type = $extends = $implements = "";
            $isInterface = $class->isInterface();
            if ($class->isAbstract()) {
                // interface 是 abstract 但是不需要abstract关键词约束
                if (!$isInterface) {
                    $modifier = "abstract ";
                }
            } else if ($class->isFinal()) {
                $modifier = "final ";
            }

            if ($class->isInterface()) {
                $type = "interface ";
            } else if ($class->isTrait()) {
                $type = "trait ";
            } else {
                $type = "class ";
            }

            if ($parent = $class->getParentClass()) {
                $extends = sprintf(" extends %s", static::getClassName($parent));
            }

            if ($interfaces = $class->getInterfaces()) {
                // 接口实现接口的关键词是extends 而不是 implements
                $implKeyword = $isInterface ? "extends" : "implements";
                $interfaces = array_map([static::class, "getClassName"], $interfaces);
                $implements = sprintf(" $implKeyword %s", implode(", ", $interfaces));
            }

            $namespace = $class->getNamespaceName();
            $shortName = $class->getShortName();
            $classLine = "{$modifier}{$type}{$shortName}{$extends}{$implements}";
            $constants = static::exportClassConstants($class->getConstants());
            $properties = static::exportClassProperties($class->getProperties(), $class->getDefaultProperties());
            $methods = static::exportClassMethods($ver, $class->getMethods());

            $classBody = "";
            if ($constants) {
                $classBody .= PHP_EOL . $constants . PHP_EOL;
            }
            if ($properties) {
                $classBody .= PHP_EOL . $properties . PHP_EOL;
            }
            if ($methods) {
                $classBody .= PHP_EOL . $methods;
            }

            $oneClass = sprintf(static::DOC_TPL_CLASS, $shortName, $ver, $namespace, $classLine, $classBody);


            if (!isset($buffer[$namespace])) {
                $buffer[$namespace] = [];
            }
            $buffer[$namespace][] = $oneClass;


            // TODO traits
            $class->getTraits();
            $class->getTraitNames();
            $class->getTraitAliases();
        }

        foreach ($buffer as $ns => $classes) {
            $tabMethods = [];
            foreach ($classes as $oneClass) {
                $tabMethods[] = static::tabLines($oneClass);
            }
            fprintf($handle, static::DOC_TPL_NAMESPACE, $ns, implode(PHP_EOL, $tabMethods));
        }
    }

    /**
     * @param ReflectionParameter[] $parameters
     * @return string
     */
    private static function exportParameters(array $parameters)
    {
        $paramList = [];
        $doc = [];

        foreach ($parameters as $parameter) {
            // $parameter->getType(); // php7
            // $parameter->hasType(); // php7
            // $parameter->allowsNull();
            // $parameter->isDefaultValueAvailable();

            if ($parameter->isVariadic()) {
                $paramList = ["/* ...\$args */"];
                break;
            }

            $para = "\$" . $parameter->getName();
            if ($parameter->isPassedByReference()) {
                $para = "&$para";
            }

            $typeHint = "";
            if ($class = $parameter->getClass()) {
                $typeHint = $class->getName() . " ";
            } else if ($parameter->isArray()) {
                $typeHint = "array ";
            } else if ($parameter->isCallable()) {
                $typeHint = "callable ";
            }


            $defaultValue = "";
            $isOptional = "";
            if ($parameter->isOptional()) {
                // Cannot determine default value for internal functions
                /*
                if ($parameter->isDefaultValueConstant()) {
                    $defaultValue = " = " . $parameter->getDefaultValueConstantName();
                } else {
                    $defaultValue = " = " . $parameter->getDefaultValue();
                }
                */
                $defaultValue = " = null";
                $isOptional = " [optional]";
            }

            $paramList[] = "{$typeHint}{$para}{$defaultValue}";

            $doc[] = sprintf(" * @param %s\$%s%s", $typeHint, $parameter->getName(), $isOptional);
        }

        return [implode(", ", $paramList), $doc];
    }

    private static function exportClassConstants(array $constants)
    {
        $ret = [];
        foreach ($constants as $key => $value) {
            if(!is_numeric($value)) {
                $value ="\"$value\"";
            }
            $ret[] = "\tconst $key = $value;";
        }
        return implode(PHP_EOL, $ret);
    }

    /**
     * @param ReflectionProperty[] $properties
     * @param array $defaultProperties
     * @return string
     */
    private static function exportClassProperties(array $properties, array $defaultProperties)
    {
        $ret = [];
        foreach ($properties as $property) {
            $static = $value = "";
            $modifier = "\t";

            if ($property->isPrivate()) {
                $modifier .= "private ";
            } else if ($property->isProtected()) {
                $modifier .= "protected ";
            } else if ($property->isPublic()) {
                $modifier .= "public ";
            }

            if ($property->isStatic()) {
                $static = "static ";
            }

            $propName = $property->getName();
            if (isset($defaultProperties[$propName])) {
                $value = $defaultProperties[$propName];
                if(!is_numeric($value)) {
                    $value ="\"$value\"";
                }
                $value = " = $value";
            }
            $ret[] = "{$modifier}{$static}\${$propName}{$value};";
        }
        return implode(PHP_EOL, $ret);
    }

    /**
     * @param $ver
     * @param ReflectionMethod[] $methods
     * @return string
     */
    private static function exportClassMethods($ver, array $methods)
    {
        $ret = [];
        foreach ($methods as $method) {
            $modifier = "";
            $isInterface = $method->getDeclaringClass()->isInterface();
            $isAbstract = $method->isAbstract();

            // interface 内的方法 不需要 abstract 关键词
            if ($isAbstract && !$isInterface) {
                $modifier .= "abstract ";
            } else if ($method->isFinal()) {
                $modifier .= "final ";
            }

            if ($method->isPrivate()) {
                $modifier .= "private ";
            } else if ($method->isProtected()) {
                $modifier .= "protected ";
            } else if ($method->isPublic()) {
                $modifier .= "public ";
            }

            if ($method->isStatic()) {
                $modifier .= "static ";
            }

            if ($method->isVariadic()) {
                $paraStr = "/* ...\$args */";
            } else {
                list($paraStr, $doc) = static::exportParameters($method->getParameters());
            }

            if ($method->isDeprecated()) {
                $doc[] = " * @deprecated";
            }

            $doc[] = " * @return"; // getType
            $doc = array_map(function($v) { return "\t$v"; }, $doc);

            $methodName = $method->getName();

            $noNeedBody = $isAbstract || $isInterface;
            $ret[] = sprintf(static::DOC_TPL_METHOD, $methodName, $ver, implode(PHP_EOL, $doc), $modifier,
                $methodName, $paraStr, $noNeedBody ? ";" : " {}");
        }

        return implode(PHP_EOL, $ret);
    }

    private static function getClassName(\ReflectionClass $class)
    {
        return "\\" . ltrim($class->getNamespaceName() . "\\" . $class->getShortName(), "\\");
    }

    private static function tabLines($linesStr)
    {
        return "\t" . str_replace(PHP_EOL, PHP_EOL . "\t", $linesStr);
    }
}
