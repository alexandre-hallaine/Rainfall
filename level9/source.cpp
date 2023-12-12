#include <cstring>
#include <cstdlib>

class N
{
private:
    char annotation[100];
    int value;

public:
    N(int val) : value(val) {}

    void setAnnotation(char *ann) { std::memcpy(this->annotation, ann, std::strlen(ann)); }

    virtual int operator+(N &other) { return this->value + other.value; }
    virtual int operator-(N &other) { return this->value - other.value; }
};

int main(int argc, char **argv)
{
    if (argc <= 1)
        exit(1);

    N *ptr1 = new N(5);
    N *ptr2 = new N(6);

    N &ref1 = *ptr1;
    N &ref2 = *ptr2;

    ref1.setAnnotation(argv[1]);

    return ref2 + ref1;
}
